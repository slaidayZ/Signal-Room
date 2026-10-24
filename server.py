#!/usr/bin/env python3
"""SIGNAL ROOM 0.3. Local, solo-only incident-response simulation.
All accounts, services, events and IP addresses are fictional. No external commands run.
Requires Python 3.9+ standard library only.
"""
from __future__ import annotations

import json
import re
import shlex
import sqlite3
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
HOST, PORT = '127.0.0.1', 3080

class Simulation:
    def __init__(self):
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        with getattr(self, 'lock', threading.RLock()):
            if getattr(self, 'db', None):
                self.db.close()
            self.db = sqlite3.connect(':memory:', check_same_thread=False)
            self.db.row_factory = sqlite3.Row
            self.db.executescript('''
            CREATE TABLE accounts (username TEXT PRIMARY KEY, team TEXT, role TEXT, status TEXT, credential_version INTEGER);
            CREATE TABLE sessions (id TEXT PRIMARY KEY, username TEXT, source_ip TEXT, device TEXT, started_at TEXT, mfa TEXT, status TEXT);
            CREATE TABLE auth_events (event_id TEXT PRIMARY KEY, time TEXT, username TEXT, source_ip TEXT, outcome TEXT, session_id TEXT, detail TEXT);
            CREATE TABLE data_events (event_id TEXT PRIMARY KEY, time TEXT, username TEXT, session_id TEXT, action TEXT, object TEXT, size_mb INTEGER);
            CREATE TABLE security_events (event_id TEXT PRIMARY KEY, time TEXT, technique TEXT, source TEXT, target TEXT, indicator TEXT, assessment TEXT, response TEXT);
            CREATE TABLE service_configs (service TEXT PRIMARY KEY, version TEXT, description TEXT);
            ''')
            self.db.executemany('INSERT INTO accounts VALUES(?,?,?,?,?)', [
                ('svc-reports','Operations','service','active',3),
                ('a.ivanova','IT','employee','active',1),
                ('m.sadyk','SOC','analyst','active',1),
                ('e.kim','Finance','employee','active',1),
            ])
            self.db.executemany('INSERT INTO sessions VALUES(?,?,?,?,?,?,?)', [
                ('S-104','a.ivanova','10.0.4.18','managed-mac','10:08','verified','active'),
                ('S-771','svc-reports','203.0.113.77','unknown-client','10:17','skipped','active'),
                ('S-772','svc-reports','10.0.6.12','report-worker-02','10:11','service-token','active'),
                ('S-319','m.sadyk','10.0.4.40','managed-workstation','10:02','verified','active'),
            ])
            self.db.executemany('INSERT INTO auth_events VALUES(?,?,?,?,?,?,?)', [
                ('AUTH-101','10:08','a.ivanova','10.0.4.18','SUCCESS','S-104','MFA verified'),
                ('AUTH-102','10:11','svc-reports','10.0.6.12','SUCCESS','S-772','Scheduled report worker'),
                ('AUTH-203','10:16','svc-reports','203.0.113.77','FAILED','','Unrecognized device'),
                ('AUTH-204','10:17','svc-reports','203.0.113.77','SUCCESS','S-771','Anomalous login; MFA skipped'),
                ('AUTH-205','10:18','m.sadyk','10.0.4.40','SUCCESS','S-319','MFA verified'),
            ])
            self.db.executemany('INSERT INTO data_events VALUES(?,?,?,?,?,?,?)', [
                ('AUD-100','10:12','svc-reports','S-772','EXPORT','daily-summary.csv',4),
                ('AUD-901','10:20','svc-reports','S-771','EXPORT','employee-index.csv',42),
                ('AUD-902','10:22','svc-reports','S-771','EXPORT','org-directory.csv',67),
            ])
            # Fictional, detection-focused telemetry. No attack commands or payloads are implemented.
            self.db.executemany('INSERT INTO security_events VALUES(?,?,?,?,?,?,?,?)', [
                ('SEC-301','10:14','IP spoofing','198.51.100.24','edge-gateway-01','Source address conflicts with upstream session metadata','Подозрение: источник мог подменять сетевой адрес. Одного IP недостаточно для атрибуции.','Сопоставить gateway, identity и endpoint-журналы; включить проверку источника на границе.'),
                ('SEC-302','10:15','Повышение привилегий','svc-reports','role: finance-admin','Необычная попытка смены роли; операция отклонена политикой','Попытка повышения привилегий заблокирована; подтверждённого изменения роли нет.','Проверить IAM-аудит и права сервисного аккаунта; сохранить минимально необходимые роли.'),
                ('SEC-303','10:16','Фишинг через почтовый шлюз','mail-gateway-02','a.ivanova','Письмо с поддельным именем отправителя помещено в карантин','Шлюз обнаружил подозрительное письмо до доставки пользователю.','Проверить карантин и правила шлюза; не открывать вложения, подтвердить отправителя по независимому каналу.'),
                ('SEC-304','10:18','MAC flooding','access-switch-03','VLAN-22','В коротком окне замечено аномальное число новых MAC-адресов','Виртуальный коммутатор зарегистрировал признаки переполнения таблицы адресов.','Проверить port-security и телеметрию коммутатора; ограничить затронутый порт по процедуре учения.'),
                ('SEC-305','10:20','Аномалия handshake','wireless-controller-01','AP-07','Повторяющиеся события аутентификации от неизвестного клиента','Есть признаки подозрительной активности вокруг Wi-Fi-аутентификации; секреты и рукопожатия не раскрываются.','Сверить журналы контроллера и точки доступа; проверить клиентские учётные данные и настройки Wi-Fi.'),
                ('SEC-306','10:21','MFA fatigue','identity-provider','m.sadyk','Серия неожиданных MFA-запросов отклонена пользователем','Пользователь сообщил о запросах, которые сам не инициировал.','Отклонить запросы, проверить активные сессии и уведомить SOC; подтвердить пользователя по доверенному каналу.'),
            ])
            self.db.execute("INSERT INTO service_configs VALUES('auth-api','v2','New release; login intermittently fails')")
            self.db.execute("INSERT INTO service_configs VALUES('report-api','v1','Stable')")
            self.db.commit()
            self.minutes = 0
            self.pins = set()
            self.notes = []
            self.history = []
            self.warnings = []
            self.last_health = False
            self.auth_running_version = 'v2'
            self.closed = False
            self.penalty = 0
            self.hints = 0
            self.export_alerts = set()
            self.inbox = [
                {'time':'10:23','sender':'NOC / диспетчер','subject':'Нестабильность авторизации','body':'С 10:21 пользователи жалуются на ошибки входа. В мониторинге выросло число ответов 5xx. Нужно выяснить, связаны ли симптомы.'},
                {'time':'10:22','sender':'SOC / сетевой мониторинг','subject':'Дополнительные сигналы угроз','body':'В security.log появились учебные детекты: возможная подмена IP, заблокированная попытка повышения привилегий, фишинг в карантине почтового шлюза, аномалия числа MAC-адресов на порту, события Wi-Fi handshake и неожиданные MFA-запросы. Проверь индикаторы и рекомендации в журнале.'},
                {'time':'10:22','sender':'SOC / автоматическая тревога','subject':'Подозрительная активность','body':'Зафиксированы нетипичные входы и выгрузки файлов. Первопричина пока неизвестна; проверьте журналы авторизации и аудита.'},
                {'time':'10:19','sender':'Release bot','subject':'Deploy auth-api v2','body':'Новая конфигурация v2 развернута в 10:19. До релиза работала v1. Обновление не проходило полноценный канареечный тест.'},
            ]
            self.activity = [{'time':'10:23','kind':'system','text':'Учебная смена началась. Все данные существуют только в симуляции.'}]

    def now(self):
        return (datetime(2026, 10, 24, 10, 23) + timedelta(minutes=self.minutes)).strftime('%H:%M')

    def rows(self, q, args=()):
        return [dict(r) for r in self.db.execute(q, args).fetchall()]

    def is_revoked(self):
        return self.rows("SELECT status FROM sessions WHERE id='S-771'")[0]['status'] == 'revoked'

    def rotated(self):
        return self.rows("SELECT credential_version FROM accounts WHERE username='svc-reports'")[0]['credential_version'] > 3

    def recovered(self):
        conf = self.rows("SELECT version FROM service_configs WHERE service='auth-api'")[0]['version']
        return conf == 'v1' and self.auth_running_version == 'v1' and self.last_health

    def goals(self):
        return [
            {'id':'investigate', 'label':'Зафиксировать две ключевые улики', 'done': 'AUTH-204' in self.pins and bool(self.pins.intersection({'AUD-901','AUD-902','AUD-903','AUD-904'})), 'hint':'Найди необычный вход и выгрузку в журналах; добавь их ID в материалы дела.'},
            {'id':'contain', 'label':'Остановить подозрительную сессию', 'done': self.is_revoked(), 'hint':'Проверь сессии одного аккаунта и отзови только подозрительную.'},
            {'id':'secure', 'label':'Сменить скомпрометированные реквизиты', 'done': self.rotated(), 'hint':'После отзыва сессии обнови учётные данные затронутого аккаунта.'},
            {'id':'recover', 'label':'Вернуть сервис и проверить его', 'done': self.recovered(), 'hint':'Проверь версию auth-api, откати неисправную конфигурацию, перезапусти и проверь health.'},
            {'id':'close', 'label':'Закрыть отчёт об инциденте', 'done': self.closed, 'hint':'Когда выполнены остальные задачи, выполни case close.'}
        ]

    def score(self):
        return max(0, 100 - self.penalty - self.hints * 4 - max(0, self.minutes-8)*2)

    def overview(self):
        with self.lock:
            return {
                'now': self.now(), 'minutes': self.minutes, 'score': self.score(),
                'incident':'SR-042', 'closed':self.closed,
                'goals':self.goals(), 'pins':sorted(self.pins), 'notes':self.notes[-20:], 'history':self.history[-35:],
                'activity':self.activity[-18:], 'inbox':self.inbox,
                'services':[
                    {'name':'auth-api','status':'HEALTHY' if self.auth_running_version=='v1' else 'DEGRADED','running':self.auth_running_version,'config':self.rows("SELECT version FROM service_configs WHERE service='auth-api'")[0]['version'],'verified':self.last_health},
                    {'name':'report-api','status':'HEALTHY','running':'v1','config':'v1','verified':True},
                    {'name':'identity-db','status':'HEALTHY','running':'sqlite-sim','config':'demo','verified':True}
                ],
                'tables':[{'name':n,'count':self.db.execute('SELECT COUNT(*) FROM "'+n+'"').fetchone()[0]} for n in ('accounts','sessions','auth_events','data_events','security_events','service_configs')],
                'warnings':self.warnings[-6:],
                'report':self.report(),
            }

    def report(self):
        return {
            'contained':self.is_revoked() and self.rotated(),
            'recovered':self.recovered(),
            'evidence':len(self.pins), 'duration_minutes':self.minutes,
            'score':self.score(), 'closed':self.closed,
            'quality': 'Отличная работа' if self.score()>=85 else ('Инцидент локализован с замечаниями' if self.score()>=60 else 'Требуется повторная тренировка'),
            'lessons':[
                'Не принимайте решение только по IP: сопоставляйте события входа, сессии и аудит действий.',
                'Отзывайте подозрительную сессию адресно; массовое отключение может нарушить работу.',
                'Для восстановления сначала устраните ошибочную конфигурацию, затем перезапустите и проверьте health.',
                'Фиксируйте доказательства и проверяйте результат каждого изменения.'
            ]
        }

    def log(self, kind, text):
        self.activity.append({'time':self.now(),'kind':kind,'text':text})
        if len(self.activity)>200: self.activity=self.activity[-200:]

    def tick(self, n=1):
        self.minutes += n
        if not self.is_revoked():
            if self.minutes>=4 and 4 not in self.export_alerts:
                self.export_alerts.add(4)
                self.db.execute("INSERT INTO data_events VALUES(?,?,?,?,?,?,?)", ('AUD-903',self.now(),'svc-reports','S-771','EXPORT','contacts-partial.csv',18))
                self.penalty += 7
                self.warnings.append('Пока сессия S-771 была активна, произошла ещё одна выгрузка.')
                self.log('danger','Новая выгрузка данных: AUD-903. Подозрительная сессия всё ещё активна.')
            if self.minutes>=8 and 8 not in self.export_alerts:
                self.export_alerts.add(8)
                self.db.execute("INSERT INTO data_events VALUES(?,?,?,?,?,?,?)", ('AUD-904',self.now(),'svc-reports','S-771','EXPORT','contact-cache.csv',24))
                self.penalty += 10
                self.warnings.append('Задержка локализации привела к дополнительной утечке.')
                self.log('danger','Дополнительная выгрузка: AUD-904.')
        self.db.commit()

    def virtual_file(self, path):
        # These are text views of fictional evidence, never real machine files.
        if path == '/home/analyst/briefing.txt':
            return ('SR-042 / Aster Operations\n10:21: Identity service errors; suspicious exports.\n'
                    'Two signals may have different root causes.\n'
                    'Investigate before applying changes.\n')
        if path == '/etc/auth-api/config.json':
            conf = self.rows("SELECT version FROM service_configs WHERE service='auth-api'")[0]['version']
            return json.dumps({'service':'auth-api','configured_version':conf,
                'running_version':self.auth_running_version,
                'last_health_check':'PASS' if self.last_health else 'not verified'},ensure_ascii=False,indent=2)
        if path == '/var/log/auth.log':
            return '\n'.join(f"{r['time']} {r['event_id']} {r['username']} {r['source_ip']} {r['outcome']} session={r['session_id']} {r['detail']}" for r in self.rows('SELECT * FROM auth_events ORDER BY time'))
        if path == '/var/log/audit.log':
            return '\n'.join(f"{r['time']} {r['event_id']} {r['action']} actor={r['username']} session={r['session_id']} object={r['object']} size={r['size_mb']}MB" for r in self.rows('SELECT * FROM data_events ORDER BY time'))
        if path == '/var/log/security.log':
            return '\n'.join(f"{r['time']} {r['event_id']} {r['technique']} source={r['source']} target={r['target']} indicator={r['indicator']}" for r in self.rows('SELECT * FROM security_events ORDER BY time'))
        if path == '/var/log/app.log':
            return ('10:19 RELEASE deployed auth-api config v2\n'
                    '10:21 ERROR auth-api token validation failure\n'
                    '10:22 WARN auth-api elevated 5xx rate\n'
                    f"{self.now()} STATUS auth-api running={self.auth_running_version}\n")
        return None

    def result(self, message, kind='info', table=None):
        obj={'message':message,'kind':kind,'time':self.now()}
        if table is not None: obj['table']=table
        return obj

    def command(self, raw):
        with self.lock:
            return self._command(raw.strip())

    def _command(self, raw):
        if not raw: return self.result('Введите команду или help.')
        if len(raw)>1200: return self.result('Слишком длинная команда.', 'error')
        self.history.append({'time':self.now(),'cmd':raw})
        low = raw.lower().strip().rstrip(';')
        if self.closed and (low.startswith(('sessions revoke ', 'accounts rotate ', 'services rollback ', 'services restart ', 'services test '))):
            return self.result('Дело уже закрыто. Для нового прохождения нажми «Новая симуляция».', 'warning')
        if low in ('help', '?'):
            return self.result('''ОСНОВНЫЕ КОМАНДЫ
help                         все подсказки по командам
ls /var/log                  посмотреть файлы журналов
cat /var/log/auth.log        прочитать файл
grep ERROR /var/log/app.log  найти строки в файле
status                       сводка инцидента
logs auth | logs audit | logs security | logs app
sessions list                активные сессии
sessions revoke S-771       отозвать указанную сессию
accounts list                учётные записи
accounts rotate <username>   обновить реквизиты аккаунта
services list                список сервисов
services inspect auth-api    проверить настройки
services rollback auth-api v1
services restart auth-api
services test auth-api       контрольная проверка

db tables                    таблицы учебной SQLite-базы
db schema <table>            структура таблицы
sql SELECT * FROM sessions;  настоящий SQL SELECT
evidence list                материалы дела
evidence pin <event_id>      прикрепить улику
case note <текст>             записать вывод в дело
case show                    отчёт о ходе расследования
case close                   завершить расследование
hint                         ненавязчивая подсказка
clear                        очистить терминал''')
        if low == 'clear': return self.result('','clear')
        if low=='pwd': return self.result('/home/analyst')
        if low in ('ls','ls /home/analyst'):
            return self.result('briefing.txt   /var/log/   /etc/auth-api/')
        if low=='ls /var/log':return self.result('auth.log   audit.log   security.log   app.log')
        if low=='ls /etc/auth-api':return self.result('config.json')
        if low.startswith('cat '):
            try:parts=shlex.split(raw)
            except ValueError:return self.result('Ошибка кавычек в команде.', 'error')
            if len(parts)!=2:return self.result('Формат: cat /var/log/auth.log','error')
            file=self.virtual_file(parts[1])
            return self.result(file if file is not None else 'Файл не найден в учебной среде.', 'info' if file is not None else 'error')
        if low.startswith('grep '):
            try:parts=shlex.split(raw)
            except ValueError:return self.result('Ошибка кавычек в команде.', 'error')
            if len(parts)!=3:return self.result('Формат: grep ERROR /var/log/app.log','error')
            file=self.virtual_file(parts[2])
            if file is None:return self.result('Файл не найден.','error')
            result='\n'.join(line for line in file.splitlines() if parts[1].casefold() in line.casefold())
            return self.result(result or 'Совпадений не найдено.')
        if low=='status':
            return self.result(f'''ИНЦИДЕНТ SR-042  •  {self.now()}
Авторизация: {'восстановлена' if self.recovered() else 'нестабильна'}
Подозрительная сессия: {'отозвана' if self.is_revoked() else 'АКТИВНА'}
Реквизиты svc-reports: {'обновлены' if self.rotated() else 'требуют проверки'}
Улики в деле: {len(self.pins)}  •  Выполнено задач: {sum(g['done'] for g in self.goals())}/5
Используйте журналы, запросы к БД и инструменты восстановления.''')
        if low=='hint':
            outstanding=next((g for g in self.goals() if not g['done']),None)
            self.hints += 1
            return self.result((outstanding['hint'] if outstanding else 'Все задачи выполнены.') + '  [–4 к игровому результату]','warning')
        if low in ('logs auth','logs audit','logs security','logs app'):
            if low=='logs auth':
                data=self.rows('SELECT * FROM auth_events ORDER BY time')
                return self.result('ЖУРНАЛ АУТЕНТИФИКАЦИИ. Сопоставьте необычные входы с сессиями.',table=data)
            if low=='logs audit':
                data=self.rows('SELECT * FROM data_events ORDER BY time')
                return self.result('ЖУРНАЛ ДОСТУПА К ДАННЫМ. Проверьте связи по session_id.',table=data)
            if low=='logs security':
                data=self.rows('SELECT * FROM security_events ORDER BY time')
                return self.result('ДЕТЕКТИРОВАННЫЕ СЕТЕВЫЕ И IDENTITY-СОБЫТИЯ. Это безопасные учебные индикаторы, не команды атаки. Сопоставляйте сигнал с источником и целью.',table=data)
            return self.result('''10:19  RELEASE     deployed auth-api config v2
10:21  ERROR       auth-api: unexpected token validation failure
10:22  WARN        auth-api: elevated 5xx response rate
10:23  NOC         login error reports increasing
Выполните services inspect auth-api для просмотра текущей конфигурации.''')
        if low=='db tables':
            return self.result('Учебная SQLite-база. Таблицы доступны через sql SELECT.',table=self.overview()['tables'])
        if low.startswith('db schema '):
            table=low.split()[-1]
            allowed={'accounts','sessions','auth_events','data_events','security_events','service_configs'}
            if table not in allowed: return self.result('Неизвестная таблица. Начните с db tables.','error')
            rows=self.rows('PRAGMA table_info("'+table+'")')
            return self.result('Схема таблицы '+table+'.',table=[{'column':r['name'],'type':r['type'],'primary_key':bool(r['pk'])} for r in rows])
        if low.startswith('sql '):
            query=raw[4:].strip().rstrip(';').strip()
            if not re.match(r'^\s*(select|with)\b',query,re.I) or ';' in query:
                return self.result('В этой версии SQL-редактор выполняет только SELECT (включая WITH ... SELECT). Изменения делайте через команды sessions/accounts/services.','error')
            try:
                steps=[0]
                def progress():
                    steps[0]+=1
                    return 1 if steps[0]>70 else 0
                self.db.set_progress_handler(progress, 1000)
                self.db.execute('PRAGMA query_only = 1')
                cur=self.db.execute(query)
                cols=[d[0] for d in cur.description] if cur.description else []
                fetched=cur.fetchmany(51)
                rows=[dict(zip(cols,row)) for row in fetched[:50]]
                return self.result(f'SQLite: {min(50,len(fetched))} строк'+(' (показаны первые 50)' if len(fetched)>50 else '')+'.',table=rows)
            except (sqlite3.Error,ValueError) as e:
                return self.result('Ошибка SQL: '+str(e),'error')
            finally:
                self.db.set_progress_handler(None,0)
                self.db.execute('PRAGMA query_only = 0')
        if low=='sessions list':
            return self.result('Сессии. Не все сессии одного пользователя подозрительные.',table=self.rows('SELECT * FROM sessions ORDER BY started_at'))
        if low.startswith('sessions revoke '):
            sid=raw.split()[-1].upper()
            rec=self.rows('SELECT * FROM sessions WHERE id=?',(sid,))
            if not rec: return self.result('Сессия не найдена. Проверьте sessions list.','error')
            if rec[0]['status']=='revoked': return self.result('Эта сессия уже отозвана.','warning')
            self.db.execute("UPDATE sessions SET status='revoked' WHERE id=?",(sid,))
            self.tick()
            if sid != 'S-771':
                self.penalty+=12
                self.log('warning','Отозвана легитимная сессия '+sid+'. Это повлияло на работу сотрудников.')
                return self.result('Сессия '+sid+' отозвана, но это была легитимная активность. –12 к результату.','warning')
            self.log('success','Заблокирована подозрительная сессия '+sid+'.')
            return self.result('Сессия '+sid+' отозвана. Новые выгрузки через неё невозможны. Теперь проверьте реквизиты аккаунта.','success')
        if low=='accounts list':
            return self.result('Учётные записи и версии их реквизитов.',table=self.rows('SELECT * FROM accounts ORDER BY username'))
        if low.startswith('accounts rotate '):
            uname=raw.split()[-1].lower()
            rec=self.rows('SELECT * FROM accounts WHERE username=?',(uname,))
            if not rec: return self.result('Аккаунт не найден.','error')
            if uname != 'svc-reports':
                self.penalty+=10
            if uname=='svc-reports' and not self.is_revoked():
                self.penalty+=5
                self.warnings.append('Реквизиты были изменены до адресного отзыва подозрительной сессии. Требуется удостовериться, что текущие токены недействительны.')
            self.db.execute('UPDATE accounts SET credential_version=credential_version+1 WHERE username=?',(uname,))
            self.tick(2)
            self.log('success' if uname=='svc-reports' else 'warning','Реквизиты обновлены: '+uname+'.')
            return self.result('Новая версия реквизитов для '+uname+' создана. Сессии остаются независимыми: проверьте их и отзовите подозрительные.','success' if uname=='svc-reports' else 'warning')
        if low=='services list':
            return self.result('Виртуальные сервисы (без реального доступа к серверам).',table=self.overview()['services'])
        if low=='services inspect auth-api':
            cfg=self.rows("SELECT * FROM service_configs WHERE service='auth-api'")[0]
            return self.result(f'''SERVICE auth-api
Текущая конфигурация: {cfg['version']}
Исполняемая версия: {self.auth_running_version}
Состояние: {'HEALTHY' if self.auth_running_version=='v1' else 'DEGRADED'}
Релиз v2 в 10:19; повышенные ошибки авторизации после обновления.
Стабильная предыдущая конфигурация: v1
Доступные операции: services rollback auth-api v1; services restart auth-api; services test auth-api''')
        if low=='services rollback auth-api v1':
            if self.rows("SELECT version FROM service_configs WHERE service='auth-api'")[0]['version']=='v1':
                return self.result('Конфигурация уже v1. Осталось применить её перезапуском.','warning')
            self.db.execute("UPDATE service_configs SET version='v1', description='Stable baseline' WHERE service='auth-api'")
            self.tick(2)
            self.log('info','Подготовлен откат auth-api до v1; для применения нужен перезапуск.')
            return self.result('Конфигурация v1 подготовлена, но работающий процесс всё ещё использует '+self.auth_running_version+'. Перезапустите сервис.','success')
        if low=='services restart auth-api':
            new_version=self.rows("SELECT version FROM service_configs WHERE service='auth-api'")[0]['version']
            self.auth_running_version=new_version
            self.last_health=False
            self.tick(2)
            self.log('info','auth-api перезапущен с конфигурацией '+new_version+'.')
            if new_version=='v2':
                self.penalty+=6
                return self.result('Сервис перезапущен, но ошибки остались: запущена проблемная v2. –6 к результату.','warning')
            return self.result('auth-api запущен с v1. Теперь проверьте его работоспособность командой services test auth-api.','success')
        if low=='services test auth-api':
            self.tick()
            self.last_health=(self.auth_running_version=='v1')
            self.log('success' if self.last_health else 'warning','Health-check auth-api: '+('PASS' if self.last_health else 'FAIL')+'.')
            return self.result('HEALTH CHECK: '+('PASS — авторизация отвечает штатно.' if self.last_health else 'FAIL — ошибки авторизации продолжаются.'),'success' if self.last_health else 'error')
        if low=='evidence list':
            return self.result('Улики, прикреплённые к делу SR-042: '+(', '.join(sorted(self.pins)) if self.pins else 'пока пусто')+'. Используйте evidence pin <ID>.')
        if low.startswith('evidence pin '):
            eid=raw.split()[-1].upper()
            found=(self.rows('SELECT event_id FROM auth_events WHERE event_id=?',(eid,))
                   or self.rows('SELECT event_id FROM data_events WHERE event_id=?',(eid,))
                   or self.rows('SELECT event_id FROM security_events WHERE event_id=?',(eid,)))
            if not found: return self.result('Событие '+eid+' не найдено в учебных журналах.','error')
            if eid in self.pins: return self.result('Улика уже добавлена.','warning')
            self.pins.add(eid)
            self.log('info','В кейс добавлена улика '+eid+'.')
            return self.result('Улика '+eid+' добавлена в дело.','success')
        if low.startswith('case note '):
            note=raw[len('case note '):].strip()
            if not note:return self.result('Напиши текст заметки после case note.','error')
            if len(note)>500:return self.result('Заметка не должна превышать 500 символов.','error')
            self.notes.append({'time':self.now(),'text':note})
            self.log('info','В кейс добавлена заметка аналитика.')
            return self.result('Заметка сохранена в деле SR-042.','success')
        if low in ('case show','report show'):
            obj=self.report()
            return self.result(f'''ДЕЛО SR-042
Материалы: {', '.join(sorted(self.pins)) or 'нет'}\nЗаметок аналитика: {len(self.notes)}
Ограничение доступа: {'выполнено' if obj['contained'] else 'не завершено'}
Восстановление: {'проверено' if obj['recovered'] else 'не подтверждено'}
Задачи: {sum(g['done'] for g in self.goals())}/5
Оценка: {obj['score']}/100
Время симуляции: {obj['duration_minutes']} мин.
Статус: {'ЗАКРЫТО' if self.closed else 'В РАБОТЕ'}''')
        if low=='case close':
            if self.closed: return self.result('Дело уже закрыто.','success')
            todo=[g['label'] for g in self.goals()[:-1] if not g['done']]
            if todo:
                return self.result('Пока нельзя закрыть дело. Не выполнено:\n• '+'\n• '.join(todo),'warning')
            self.tick()
            self.closed=True
            self.log('success','Инцидент SR-042 закрыт. Итоговый отчёт готов.')
            return self.result('ИНЦИДЕНТ ЗАКРЫТ. Все обязательные задачи выполнены. Итоговая оценка: '+str(self.score())+'/100. Откройте вкладку «Отчёт».','success')
        return self.result('Неизвестная команда. Введите help — там есть синтаксис и примеры.','error')

SIM = Simulation()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def _json(self, data, status=200):
        out=json.dumps(data,ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length',str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    def do_GET(self):
        path=urlparse(self.path).path
        if path=='/api/state': return self._json(SIM.overview())
        rel={'/':'index.html','/index.html':'index.html','/app.js':'app.js','/style.css':'style.css'}.get(path)
        if not rel:
            self.send_error(404);return
        target=ROOT/'static'/rel
        if not target.is_file(): self.send_error(404);return
        mime={'html':'text/html','js':'application/javascript','css':'text/css'}[rel.split('.')[-1]]
        b=target.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type',mime+'; charset=utf-8')
        self.send_header('Content-Length',str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_POST(self):
        path=urlparse(self.path).path
        n=int(self.headers.get('Content-Length','0'))
        if n<0 or n>10000: return self._json({'error':'Превышен лимит размера запроса'},413)
        try: data=json.loads(self.rfile.read(n).decode()) if n else {}
        except Exception: return self._json({'error':'Некорректный JSON'},400)
        if path=='/api/reset':
            SIM.reset()
            return self._json({'state':SIM.overview()})
        if path=='/api/command':
            cmd=data.get('command','')
            if not isinstance(cmd,str):return self._json({'error':'Command must be a string'},400)
            result=SIM.command(cmd)
            return self._json({'result':result,'state':SIM.overview()})
        self._json({'error':'Неизвестный адрес'},404)

def main():
    import argparse, webbrowser
    parser=argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=PORT)
    parser.add_argument('--no-browser',action='store_true')
    args=parser.parse_args()
    server=ThreadingHTTPServer((HOST,args.port),Handler)
    print(f'\nSIGNAL ROOM 0.3 — SOLO INCIDENT LAB\nОткройте: http://{HOST}:{args.port}\nОстановка: Control + C\n')
    if not args.no_browser:
        try: webbrowser.open(f'http://{HOST}:{args.port}')
        except Exception: pass
    try:server.serve_forever()
    except KeyboardInterrupt: print('\nИгра остановлена.')
    finally:server.server_close()

if __name__=='__main__':main()
