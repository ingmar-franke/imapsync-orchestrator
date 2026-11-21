"""Offline regression checks with synthetic configuration and diagnostics."""
import importlib.util
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('orchestrator', ROOT / 'imap_orchestrator.py')
mod = importlib.util.module_from_spec(SPEC)
with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                if not k.startswith('IMAP_')}, clear=True):
    SPEC.loader.exec_module(mod)


class ConfigTests(unittest.TestCase):
    def configured_env(self):
        return dict(IMAP_SOURCE_HOST='imap.example.org', IMAP_TARGET_HOST='imap.example.org',
                    IMAP_SOURCE_USER='source@example.org', IMAP_TARGET_USER='target@example.org',
                    IMAP_OAUTH_REFRESH_SCRIPT='/private/example/oauth_refresh.py',
                    IMAP_ACCESS_TOKEN_FILE='/private/example/access_token.txt')

    def test_account_defaults_are_empty(self):
        self.assertEqual((mod.SRC, mod.DST, mod.USER1, mod.USER2), ('', '', '', ''))

    def test_missing_configuration_fails_before_network_access(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'Konfiguration fehlt'):
                mod.validate_config()

    def test_work_directory_inside_code_tree_is_rejected(self):
        with mock.patch.dict(os.environ, self.configured_env(), clear=True), \
             mock.patch.object(mod, 'ROOT', ROOT / 'runtime'):
            with self.assertRaisesRegex(RuntimeError, 'IMAP_WORK_DIR.*ausserhalb'):
                mod.validate_config()

    def test_token_inside_code_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.dict(os.environ, self.configured_env(), clear=True), \
             mock.patch.object(mod, 'ROOT', Path(temp)), \
             mock.patch.object(mod, 'TOKEN', ROOT / 'access_token.txt'):
            with self.assertRaisesRegex(RuntimeError, 'IMAP_ACCESS_TOKEN_FILE.*ausserhalb'):
                mod.validate_config()

    def test_source_has_no_literal_mailbox_or_personal_home(self):
        source = (ROOT / 'imap_orchestrator.py').read_text()
        self.assertFalse(re.search(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', source))
        self.assertFalse(re.search(r'/(?:Users|home)/[^\s/\'\"]+', source))

    def test_localized_swap_fixture(self):
        self.assertEqual(mod.parse_swap_used_mib('used = 1,50G'), 1536.0)

    def test_oauth_helper_failure_does_not_echo_output(self):
        sample = 'synthetic-private-output'
        result = mock.Mock(returncode=7, stderr=sample, stdout=sample)
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(mod, 'ROOT', Path(temp)), \
             mock.patch.object(mod.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError) as raised:
                mod.refresh_oauth()
        self.assertNotIn(sample, str(raised.exception))
        self.assertIn('Exit 7', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
