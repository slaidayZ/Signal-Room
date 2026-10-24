"""Automated regression tests for the local, simulated incident lab."""
import http.client
import json
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
from server import Simulation


class GameTests(unittest.TestCase):
    def setUp(self):
        self.s = Simulation()

    def tearDown(self):
        self.s.close()

    def send(self, command):
        return self.s.command(command)

    def finish(self):
        self.send('evidence pin AUTH-204')
        self.send('evidence pin AUD-901')
        for event_id in sorted(self.s.active_security_ids):
            self.send('evidence pin ' + event_id)
        self.send('sessions revoke S-771')
        for event_id in sorted(self.s.security_to_contain):
            self.send('security contain ' + event_id)
        self.send('accounts rotate svc-reports')
        self.send('services rollback auth-api v1')
        self.send('services restart auth-api')
        self.send('services test auth-api')
        self.assertTrue(all(goal['done'] for goal in self.s.goals()[:-1]))
        return self.send('case close')

    def test_clean_win(self):
        self.assertTrue(any(not goal['done'] for goal in self.s.goals()))
        self.assertIn('AUTH-204', [r['event_id'] for r in self.send('logs auth')['table']])
        self.assertIn('AUD-901', [r['event_id'] for r in self.send('logs audit')['table']])
        self.assertEqual(len(self.send("sql SELECT * FROM sessions WHERE username='svc-reports';")['table']), 2)
        self.assertEqual(self.finish()['kind'], 'success')
        self.assertTrue(self.s.closed)
        self.assertTrue(all(g['done'] for g in self.s.goals()))
        self.assertGreaterEqual(self.s.score(), 90)

    def test_all_modes_can_win(self):
        for mode in ('all', 'random'):
            with self.subTest(mode=mode):
                self.s.reset(mode)
                self.assertEqual(self.s.overview()['mode'], mode)
                self.assertTrue(3 <= len(self.s.active_security_ids) <= 6)
                self.assertEqual(self.finish()['kind'], 'success')
                self.assertTrue(self.s.report()['contained'])

    def test_random_mode_only_selects_visible_events(self):
        for _ in range(8):
            self.s.reset('random')
            ids = {r['event_id'] for r in self.send('logs security')['table']}
            self.assertEqual(ids, self.s.active_security_ids)
            objective = next(g for g in self.s.goals() if g['id'] == 'investigate_security')
            self.assertIn(str(len(ids)), objective['label'])

    def test_cannot_finish_without_evidence(self):
        self.assertEqual(self.send('case close')['kind'], 'warning')
        self.assertFalse(self.s.closed)

    def test_wrong_session_penalty(self):
        self.send('sessions revoke S-772')
        self.assertFalse(self.s.is_revoked())
        self.assertLess(self.s.score(), 100)

    def test_delay_causes_additional_export(self):
        for _ in range(4):
            self.send('services restart auth-api')
        ids = [r['event_id'] for r in self.send('logs audit')['table']]
        self.assertIn('AUD-903', ids)

    def test_sql_is_read_only(self):
        for query in (
            "sql UPDATE sessions SET status='revoked' WHERE id='S-771';",
            'sql WITH del AS (DELETE FROM sessions RETURNING *) SELECT * FROM del;',
            'sql SELECT 1; DELETE FROM sessions;',
            'sql PRAGMA writable_schema=ON;',
        ):
            with self.subTest(query=query):
                self.assertEqual(self.send(query)['kind'], 'error')
        self.assertFalse(self.s.is_revoked())
        self.assertEqual(len(self.send('sql SELECT * FROM sessions;')['table']), 4)

    def test_sql_query_bounded(self):
        self.assertEqual(self.send('sql SELECT * FROM sessions;')['kind'], 'info')
        self.assertEqual(self.send('sql SELECT hex(zeroblob(200000));')['kind'], 'error')

    def test_virtual_shell_and_notes(self):
        self.assertIn('auth.log', self.send('ls /var/log')['message'])
        self.assertIn('AUTH-204', self.send('cat /var/log/auth.log')['message'])
        self.assertIn('ERROR', self.send('grep ERROR /var/log/app.log')['message'])
        self.assertIn('v2', self.send('cat /etc/auth-api/config.json')['message'])
        self.assertEqual(self.send('case note Проверить журнал авторизации')['kind'], 'success')
        self.assertEqual(len(self.s.overview()['notes']), 1)

    def test_alternate_export_evidence_is_accepted(self):
        self.send('evidence pin AUTH-204')
        self.send('evidence pin AUD-902')
        self.assertTrue(self.s.goals()[0]['done'])

    def test_real_sql_join(self):
        rows = self.send('sql SELECT s.id, d.event_id FROM sessions s JOIN data_events d ON s.id=d.session_id;')['table']
        self.assertTrue(any(r['id']=='S-771' and r['event_id']=='AUD-901' for r in rows))

    def test_containment_statuses_are_idempotent(self):
        self.assertEqual(self.send('security contain SEC-301')['kind'], 'success')
        score = self.s.score()
        self.assertEqual(self.send('security contain SEC-301')['kind'], 'warning')
        self.assertEqual(self.send('security contain SEC-303')['kind'], 'warning')
        self.assertEqual(self.s.score(), score)
        obj = next(g for g in self.s.goals() if g['id'] == 'contain_security')
        self.assertIn('4', obj['label'])
        self.assertFalse(obj['done'])

    def test_unknown_command_safe(self):
        self.assertEqual(self.send('rm -rf /')['kind'], 'error')

    def test_reset_clears_console_and_session(self):
        self.send('sessions revoke S-771')
        self.assertTrue(self.s.overview()['console'])
        self.s.reset()
        self.assertFalse(self.s.is_revoked())
        self.assertEqual(self.s.minutes, 0)
        self.assertEqual(self.s.overview()['console'], [])
        self.assertTrue(self.s.overview()['started'])

    def test_clear_console(self):
        self.send('help')
        self.assertTrue(self.s.console)
        self.send('clear')
        self.assertEqual(self.s.console, [])

    def test_closed_score_is_stable(self):
        self.finish()
        final = self.s.score()
        self.send('hint')
        self.send('case close')
        self.assertEqual(self.s.score(), final)

    def test_state_dynamic_config(self):
        self.send('services rollback auth-api v1')
        self.assertNotEqual(self.s.overview()['services'][0]['status'], 'HEALTHY')
        self.send('services restart auth-api')
        self.assertEqual(self.s.overview()['services'][0]['status'], 'HEALTHY')
        self.assertFalse(self.s.recovered())
        self.send('services test auth-api')
        self.assertTrue(self.s.recovered())

    def test_no_external_network_interfaces(self):
        self.assertEqual(server.HOST, '127.0.0.1')


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.webserver = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        cls.port = cls.webserver.server_port
        cls.thread = threading.Thread(target=cls.webserver.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.webserver.shutdown()
        cls.webserver.server_close()
        cls.thread.join(2)

    def request(self, method, path, body=None, headers=None):
        conn=http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request(method,path,body=body,headers=headers or {})
        r=conn.getresponse()
        status=r.status
        response_headers=dict(r.getheaders())
        data=r.read()
        conn.close()
        return status,response_headers,data

    def test_get_state_and_static(self):
        status, headers, body=self.request('GET','/api/state')
        self.assertEqual(status,200)
        self.assertIn('goals', json.loads(body))
        self.assertEqual(headers.get('Cache-Control'),'no-store')
        for path in ('/', '/app.js', '/style.css'):
            code, h, _=self.request('GET',path)
            self.assertEqual(code,200)
            self.assertEqual(h.get('Cache-Control'),'no-store')
        self.assertEqual(self.request('GET','/no-such-file')[0],404)

    def test_reset_and_command(self):
        headers={'Content-Type':'application/json', 'Origin':f'http://127.0.0.1:{self.port}'}
        code, _, response=self.request('POST','/api/reset',json.dumps({'mode':'random'}),headers)
        self.assertEqual(code,200)
        self.assertEqual(json.loads(response)['state']['mode'],'random')
        code, _, response=self.request('POST','/api/command',json.dumps({'command':'status'}),headers)
        self.assertEqual(code,200)
        self.assertIn('ИНЦИДЕНТ',json.loads(response)['result']['message'])
        headers['Origin'] = f'http://localhost:{self.port}'
        self.assertEqual(self.request('POST','/api/command',json.dumps({'command':'help'}),headers)[0], 200)

    def test_request_validation(self):
        good={'Content-Type':'application/json'}
        cases=[
            ('[]', good,400),
            ('{broken json', good,400),
            ('{"command": 7}', good,400),
            ('{"command":"status"}', {'Content-Type':'text/plain'},415),
            ('{"command":"status"}', {'Content-Type':'application/json','Origin':'https://random-site.example'},403),
            ('{"command":"status"}', {'Content-Type':'application/json','Content-Length':'not-an-int'},400),
        ]
        for body, headers, expected in cases:
            with self.subTest(body=body,headers=headers):
                code, _, _ = self.request('POST','/api/command',body,headers)
                self.assertEqual(code, expected)


if __name__ == '__main__':
    unittest.main()
