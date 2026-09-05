import contextlib
import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from eacp_hardening import cli
from eacp_hardening.common import Principal, VerifiedEvent
from eacp_hardening.operations import OperationalStore
from eacp_hardening.demo import fixture

OP = Principal('operator', 'demo', frozenset({'writer', 'reader', 'operator'}))
NOW = '2026-09-05T06:00:00Z'


class FaultTests(unittest.TestCase):
    def test_F01_process_exit_before_commit_after_commit_and_after_ack(self):
        code = '''
import sys,os
from eacp_hardening.common import Principal,VerifiedEvent
from eacp_hardening.operations import OperationalStore
p=Principal('operator','demo',frozenset({'writer','operator','reader'}))
e=VerifiedEvent('demo','source','one',1,'2026-09-05T06:00:00Z',{'synthetic':True},'collector','key','2026-09-05T06:00:00Z')
s=OperationalStore(sys.argv[1],b'z'*32)
if sys.argv[2]=='before':
    with s._transaction():
        s.enqueue(p,e)
        os._exit(81)
s.enqueue(p,e)
if sys.argv[2]=='ack':
    print('ACK one',flush=True)
os._exit(82)
'''
        with tempfile.TemporaryDirectory() as d:
            for phase, expected in [('before', 0), ('after', 1), ('ack', 1)]:
                path = Path(d) / (phase + '.sqlite')
                result = subprocess.run([sys.executable, '-c', code, str(path), phase], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 81 if phase == 'before' else 82, result.stderr)
                self.assertEqual(b'ACK' in result.stdout, phase == 'ack')
                with OperationalStore(path, b'z' * 32) as store:
                    self.assertEqual(store.status(OP, 'source')['pending_count'], expected)
                    if expected:
                        event = VerifiedEvent('demo', 'source', 'one', 1, NOW, {'synthetic': True}, 'collector', 'key', NOW)
                        self.assertEqual(store.enqueue(OP, event)['status'], 'duplicate')
                        store.drain(OP)
                        self.assertEqual(store.read_events(OP, 'source')[0]['event_id'], 'one')

    def test_F02_sqlite_page_quota_full_then_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            with OperationalStore(Path(d) / 'store.sqlite', b'z' * 32) as store:
                pages = store._db.execute('PRAGMA page_count').fetchone()[0]
                store._db.execute('PRAGMA max_page_count=' + str(pages + 3))
                large = VerifiedEvent('demo', 'source', 'large', 1, NOW, {'synthetic': 'x' * 65536}, 'collector', 'key', NOW)
                with self.assertRaises(sqlite3.OperationalError) as caught:
                    store.enqueue(OP, large)
                self.assertEqual(caught.exception.sqlite_errorcode, sqlite3.SQLITE_FULL)
                store._db.execute('PRAGMA max_page_count=10000')
                self.assertEqual(store.status(OP, 'source')['pending_count'], 0)
                self.assertEqual(store.enqueue(OP, large)['status'], 'queued')
                self.assertEqual(store.drain(OP), 1)
                self.assertEqual(store.read_events(OP, 'source')[0]['payload'], large.payload)

    def test_F03_readonly_and_busy_errors_are_safe_cli_failures(self):
        config, token, *_ = fixture(NOW)
        for code in ('read-only database with PRIVATE_CANARY', 'database locked PRIVATE_CANARY'):
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(cli, 'load_json', return_value=config), \
                 mock.patch.object(cli, 'now_utc', return_value=NOW), \
                 mock.patch.dict('os.environ', {'EACP_ACCESS_TOKEN': token, 'EACP_STORAGE_KEY_HEX': '11' * 32}), \
                 mock.patch.object(cli, 'OperationalStore', side_effect=sqlite3.OperationalError(code)), \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = cli.main(['diagnostics', '--database', 'not-created', '--config', 'synthetic', '--source', 'delivery'])
            self.assertEqual(result, 2)
            self.assertEqual(json.loads(stderr.getvalue())['status'], 'error')
            self.assertNotIn('PRIVATE_CANARY', stderr.getvalue())
            self.assertNotIn('Traceback', stderr.getvalue())

    def test_F04_full_disk_page_rolls_back_cursor_without_masking_error(self):
        with tempfile.TemporaryDirectory() as d:
            with OperationalStore(Path(d) / 'store.sqlite', b'z' * 32) as store:
                pages = store._db.execute('PRAGMA page_count').fetchone()[0]
                store._db.execute('PRAGMA max_page_count=' + str(pages + 3))
                event = VerifiedEvent('demo', 'source', 'large', 1, NOW, {'synthetic': 'x' * 65536}, 'collector', 'key', NOW)
                with self.assertRaises(sqlite3.OperationalError) as caught:
                    store.enqueue_page(OP, 'source', [event], expected_cursor=None, next_cursor='page-1')
                self.assertEqual(caught.exception.sqlite_errorcode, sqlite3.SQLITE_FULL)
                store._db.execute('PRAGMA max_page_count=10000')
                self.assertIsNone(store.cursor(OP, 'source'))
                self.assertEqual(store.status(OP, 'source')['pending_count'], 0)
