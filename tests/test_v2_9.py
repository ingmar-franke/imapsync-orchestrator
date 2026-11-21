"""Synthetic regression and privacy checks for the optional v2.9 continuation."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / 'imap_orchestrator_v2_9.py'
SPEC = importlib.util.spec_from_file_location('orchestrator_v29', MODULE_PATH)
mod = importlib.util.module_from_spec(SPEC)
with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                if not k.startswith('IMAP_')}, clear=True):
    SPEC.loader.exec_module(mod)


class PublicV29Tests(unittest.TestCase):
    def configured_env(self):
        return dict(IMAP_SOURCE_HOST='imap.example.org', IMAP_TARGET_HOST='imap.example.org',
                    IMAP_SOURCE_USER='source@example.org', IMAP_TARGET_USER='target@example.org',
                    IMAP_OAUTH_REFRESH_SCRIPT='/private/example/oauth_refresh.py',
                    IMAP_ACCESS_TOKEN_FILE='/private/example/access_token.txt')

    def test_blank_account_defaults_and_gap_policy(self):
        self.assertEqual((mod.SRC, mod.DST, mod.USER1, mod.USER2), ('', '', '', ''))
        self.assertEqual(mod.ALLOWED_SOURCE_GAPS, ())

    def test_configuration_fails_before_network(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'Konfiguration fehlt'):
                mod.validate_config()

    def test_runtime_path_cannot_be_in_source_checkout(self):
        with mock.patch.dict(os.environ, self.configured_env(), clear=True), \
             mock.patch.object(mod, 'ROOT', ROOT / 'runtime'):
            with self.assertRaisesRegex(RuntimeError, 'IMAP_WORK_DIR.*ausserhalb'):
                mod.validate_config()

    def test_token_path_cannot_be_in_source_checkout(self):
        with mock.patch.dict(os.environ, self.configured_env(), clear=True), \
             mock.patch.object(mod, 'TOKEN', ROOT / 'access_token.txt'):
            with self.assertRaisesRegex(RuntimeError, 'IMAP_ACCESS_TOKEN_FILE.*ausserhalb'):
                mod.validate_config()

    def test_explicit_gap_validation(self):
        with mock.patch.dict(os.environ, {'IMAP_ALLOWED_MISSING_UIDS': '13, 14'}):
            self.assertEqual(mod.configured_source_gaps(), (13, 14))
        for value in ('1,1', '0', 'text', '4294967296'):
            with self.subTest(value=value), mock.patch.dict(os.environ, {'IMAP_ALLOWED_MISSING_UIDS': value}):
                with self.assertRaises(RuntimeError):
                    mod.configured_source_gaps()

    def test_snapshot_fail_closed_without_explicit_gap(self):
        original = [1, 3, 7, 11]
        rows = [(1, 7, 3), (11, 11, 1)]
        state = dict(snapshot_count=4, snapshot_max_uid=11,
                     source_uid_sha256=mod.digest_uids(original))
        with self.assertRaisesRegex(RuntimeError, 'Quell-Snapshot weicht'):
            mod.verify_original_snapshot(state, rows, [1, 3, 7])
        restored, missing, new = mod.verify_original_snapshot(state, rows, [1, 3, 7],
                                                               allowed_missing=(11,))
        self.assertEqual((restored, missing, new), (original, (11,), 0))

    def test_schema2_upgrades_without_moving_touched_cache(self):
        rows = [(1 + i*200, (i+1)*200, 200) for i in range(8)]
        state = dict(schema=2, source_uid_sha256=mod.digest_uids(list(range(1,1601))),
                     manifest_sha256=hashlib.sha256(''.join(f'{a}\t{b}\t{n}\n' for a,b,n in rows).encode()).hexdigest(),
                     snapshot_count=1600, snapshot_max_uid=1600,
                     completed=[0], in_progress={'0':[1], '1':[4]},
                     attempts={'0':1,'1':1,'4':1}, results={})
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            mapping, meta=mod.build_or_validate_lane_plan(state, rows, root/'logs',root)
            self.assertEqual(mapping['0'], 0)
            self.assertEqual(mapping['1'], 0)
            self.assertEqual(mapping['4'], 1)
            state.update(schema=3, cache_lane_plan=meta)
            again,_=mod.build_or_validate_lane_plan(state, rows, root/'logs',root)
            self.assertEqual(mapping,again)
            corrupted=copy.deepcopy(state)
            corrupted['cache_lane_plan']['mapping']['0']=3
            with self.assertRaises(RuntimeError):
                mod.build_or_validate_lane_plan(corrupted, rows, root/'logs',root)

    def test_throttle_and_log_copy_parser(self):
        self.assertEqual(mod.copied_log_metrics('msg INBOX/1 {128} copied to INBOX/19\n'
                                                'msg INBOX/1 {128} copied to INBOX/20\n'), (1,128))
        self.assertEqual(mod.throttle_details('Request is throttled Backoff Time: 1000 milliseconds'),
                         (True,1.0))

    def test_oauth_refresh_failure_does_not_echo_secret(self):
        fake=mock.Mock(returncode=8, stderr='synthetic-secret-marker', stdout='synthetic-secret-marker')
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(mod, 'ROOT', Path(tmp)), \
             mock.patch.object(mod.subprocess, 'run', return_value=fake):
            with self.assertRaises(RuntimeError) as raised:
                mod.refresh_oauth()
            self.assertNotIn('synthetic-secret-marker', str(raised.exception))
            self.assertIn('Exit 8', str(raised.exception))

    def test_source_contains_no_live_identity_or_credentials(self):
        content=MODULE_PATH.read_text()
        self.assertNotRegex(content, r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
        self.assertNotRegex(content, r'/(?:Users|home)/[^\s/\'"]+')
        self.assertNotRegex(content, r"(?im)^\s*(?:SRC|DST|USER1|USER2)\s*=\s*['\"]")
        self.assertNotRegex(content, r'\bALLOWED_SOURCE_GAPS\s*=\s*\(\d+')
        self.assertNotIn('--delete2', content)
        self.assertNotIn('--delete1', content)


if __name__ == '__main__':
    unittest.main()
