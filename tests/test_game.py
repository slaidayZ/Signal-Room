import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from server import Simulation

class GameTests(unittest.TestCase):
    def setUp(self):
        self.s=Simulation()
    def send(self,command):
        return self.s.command(command)
    def test_clean_win(self):
        self.assertTrue(any(not t['done'] for t in self.s.goals()))
        self.assertIn('AUTH-204',[r['event_id'] for r in self.send('logs auth')['table']])
        self.assertIn('AUD-901',[r['event_id'] for r in self.send('logs audit')['table']])
        self.assertEqual(len(self.send("sql SELECT * FROM sessions WHERE username='svc-reports';")['table']),2)
        self.send('evidence pin AUTH-204')
        self.send('evidence pin AUD-901')
        self.send('sessions revoke S-771')
        self.send('accounts rotate svc-reports')
        self.send('services rollback auth-api v1')
        self.send('services restart auth-api')
        self.send('services test auth-api')
        self.assertTrue(all(t['done'] for t in self.s.goals()[:-1]))
        result=self.send('case close')
        self.assertEqual(result['kind'],'success')
        self.assertTrue(self.s.closed)
        self.assertTrue(all(t['done'] for t in self.s.goals()))
        self.assertGreaterEqual(self.s.score(),90)
    def test_cannot_finish_without_evidence(self):
        result=self.send('case close')
        self.assertEqual(result['kind'],'warning')
        self.assertFalse(self.s.closed)
    def test_wrong_session_penalty(self):
        self.send('sessions revoke S-772')
        self.assertFalse(self.s.is_revoked())
        self.assertLess(self.s.score(),100)
    def test_delay_causes_additional_export(self):
        for _ in range(4):
            self.send('services restart auth-api')
        ids=[r['event_id'] for r in self.send('logs audit')['table']]
        self.assertIn('AUD-903', ids)
    def test_sql_is_read_only(self):
        response=self.send("sql UPDATE sessions SET status='revoked' WHERE id='S-771';")
        self.assertEqual(response['kind'],'error')
        response=self.send("sql WITH del AS (DELETE FROM sessions RETURNING *) SELECT * FROM del;")
        self.assertEqual(response['kind'],'error')
        self.assertFalse(self.s.is_revoked())
        self.assertEqual(len(self.send('sql SELECT * FROM sessions;')['table']),4)
    def test_virtual_shell_and_notes(self):
        self.assertIn('auth.log',self.send('ls /var/log')['message'])
        self.assertIn('AUTH-204',self.send('cat /var/log/auth.log')['message'])
        self.assertIn('ERROR',self.send('grep ERROR /var/log/app.log')['message'])
        self.assertIn('v2',self.send('cat /etc/auth-api/config.json')['message'])
        self.assertEqual(self.send('case note Проверить журнал авторизации')['kind'],'success')
        self.assertEqual(len(self.s.overview()['notes']),1)
    def test_alternate_export_evidence_is_accepted(self):
        self.send('evidence pin AUTH-204')
        self.send('evidence pin AUD-902')
        self.assertTrue(self.s.goals()[0]['done'])
    def test_real_sql_join(self):
        table=self.send('sql SELECT s.id, d.event_id FROM sessions s JOIN data_events d ON s.id=d.session_id;')['table']
        self.assertTrue(any(r['id']=='S-771' and r['event_id']=='AUD-901' for r in table))
    def test_unknown_command_safe(self):
        self.assertEqual(self.send('rm -rf /')['kind'],'error')
    def test_reset(self):
        self.send('sessions revoke S-771')
        self.s.reset()
        self.assertFalse(self.s.is_revoked())
        self.assertEqual(self.s.minutes,0)
    def test_state_dynamic_config(self):
        self.send('services rollback auth-api v1')
        self.assertNotEqual(self.s.overview()['services'][0]['status'],'HEALTHY')
        self.send('services restart auth-api')
        self.assertEqual(self.s.overview()['services'][0]['status'],'HEALTHY')
        self.assertFalse(self.s.recovered())
        self.send('services test auth-api')
        self.assertTrue(self.s.recovered())
    def test_no_external_network_interfaces(self):
        from server import HOST
        self.assertEqual(HOST,'127.0.0.1')

if __name__=='__main__': unittest.main()
