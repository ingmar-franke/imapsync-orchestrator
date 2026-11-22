"""Synthetic regression tests: no real mailbox data or network connection."""
import os
import subprocess
import sys
import unittest
from collections import Counter
from email import policy
from email.parser import BytesParser
from pathlib import Path

from archive_tools import config
from archive_tools import archive_audit, delta_inbox, delta_sent
from archive_tools import inbox_header_diagnostics as ih
from archive_tools import mime_detail, mime_visible, mime_validator, duplicate_counts

class SafetyTests(unittest.TestCase):
    def test_no_online_with_empty_environment(self):
        old = {name: os.environ.pop(name, None) for name in
               ('IMAP_SOURCE_HOST', 'IMAP_TARGET_HOST', 'IMAP_SOURCE_USER', 'IMAP_TARGET_USER')}
        try:
            with self.assertRaisesRegex(RuntimeError, 'explicit settings'):
                config.require_online()
        finally:
            for key, value in old.items():
                if value is not None:
                    os.environ[key] = value

    def test_delta_apps_independent_checkpoints(self):
        self.assertNotEqual(delta_inbox.STATE, delta_sent.STATE)
        self.assertNotEqual(delta_inbox.CACHE, delta_sent.CACHE)

    def test_missing_email_mid_matching_is_one_to_one(self):
        mk = lambda uid, mid='': dict(uid=uid,msg_id=mid,signature='s1',
               meta_signature='m1',no_id_signature='n1',received_count=0,size_bytes=20)
        strict,fallback,unmatched,extra=ih.match([mk(1),mk(2)],[mk(100)])
        self.assertEqual(len(strict),1)
        self.assertEqual(len(unmatched),1)
        self.assertEqual(len(extra),0)

    def test_ambiguous_mid_not_unique(self):
        mk=lambda uid: dict(uid=uid,msg_id='id',signature='same',
                  meta_signature='meta',no_id_signature='',received_count=0,size_bytes=10)
        pairs,fb,missing,extras=ih.match([mk(1),mk(2)],[mk(10)])
        self.assertEqual((len(pairs),len(missing),len(extras)),(1,1,0))

    def test_digest_uid_order_sensitive(self):
        self.assertNotEqual(archive_audit.digest_uids([1,2]),archive_audit.digest_uids([2,1]))

    def test_html_visible_text_and_link(self):
        raw_a=b'Content-Type: text/html; charset=utf-8\r\n\r\n<div>Hello <b>world</b> <a href="https://example.org/a">x</a></div>'
        raw_b=b'Content-Type: text/html; charset=utf-8\r\n\r\n<div>Hello <i>world</i> <a href="https://example.org/a">x</a></div>'
        raw_c=b'Content-Type: text/html; charset=utf-8\r\n\r\n<div>Hello <i>world</i> <a href="https://example.org/b">x</a></div>'
        a=mime_visible.fingerprint_message(raw_a)
        b=mime_visible.fingerprint_message(raw_b)
        c=mime_visible.fingerprint_message(raw_c)
        self.assertEqual(mime_visible.compare_messages(a,b)['verdict'],'SICHTTEXT_UND_LINKS_GLEICH')
        self.assertNotEqual(mime_visible.compare_messages(a,c)['verdict'],'SICHTTEXT_UND_LINKS_GLEICH')

    def test_mime_parts_and_headers_comparison(self):
        x=b'Message-ID: <a@e.invalid>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\n'
        y=b'Message-ID: <a@e.invalid>\r\nX-Custom: header\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\n'
        a=mime_detail.inspect_message(x)
        b=mime_detail.inspect_message(y)
        self.assertEqual(a['parts'][0]['payload_sha256'],b['parts'][0]['payload_sha256'])
        self.assertEqual(mime_detail.one_to_one_diff(a,b)['classification'],'IDENTISCHE_NUTZDATEN_MIME_ODER_HEADER_DIFFERENZ')

    def test_duplicate_mime_hash_deterministic(self):
        x=b'Content-Type: text/plain; charset=utf-8\r\n\r\nExample\r\n'
        self.assertEqual(mime_validator.mime_evidence(x)['mime_sha256'],
                         mime_validator.mime_evidence(x)['mime_sha256'])

    def test_help_does_not_connect(self):
        cwd=Path(__file__).resolve().parents[2]
        for module in ('duplicate_headers','duplicate_mime','delta_inbox','delta_sent',
                       'mime_validator','mime_detail','mime_visible','inbox_header_diagnostics'):
            cp=subprocess.run([sys.executable,'-m',f'archive_tools.{module}','--help'],
                              cwd=cwd,capture_output=True,text=True,timeout=5)
            self.assertEqual(cp.returncode,0,(module,cp.stderr[:200]))

if __name__=='__main__':
    unittest.main()

class PublicationHardeningTests(unittest.TestCase):
    """Additional independent tests of privacy and cross-named folder support."""

    def test_quote_imap_folder_prevents_command_injection(self):
        self.assertEqual(config.quote_imap_folder('Sent Items'), '"Sent Items"')
        for bad in ('', 'a"b', 'a\\b', 'a\nb', 'a\rb', 'a\x00b'):
            with self.subTest(name=repr(bad)), self.assertRaises(ValueError):
                config.quote_imap_folder(bad)

    def test_duplicate_mime_never_publishes_plain_filenames(self):
        from archive_tools import duplicate_mime
        name = 'sensitive'+'-contract.xlsx'
        raw = (b'Content-Type: application/octet-stream\r\n'
               + b'Content-Disposition: attachment; filename="' + name.encode() + b'"\r\n'
               + b'Content-Transfer-Encoding: base64\r\n\r\nYWJj\r\n')
        _, attachments, _ = duplicate_mime.signatures(raw)
        self.assertEqual(len(attachments), 1)
        self.assertNotIn(name, str(attachments))
        self.assertEqual(len(attachments[0][1]), 64)

    def test_folder_audit_with_different_destination_name(self):
        from unittest import mock
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            db=archive_audit.open_db(root/'index.sqlite3')
            try:
                for side,folder,uid in [('source','Sent',17),('target','Sent Items',101)]:
                    uids_hash=archive_audit.digest_uids([uid])
                    db.execute('INSERT INTO folders VALUES(?,?,?,?,?)',
                               (side,folder,'3',uids_hash,1))
                    db.execute('INSERT INTO headers VALUES(?,?,?,?,?,?,?,?,?)',
                               (side,folder,uid,'id','strong','meta','noid',1,1234))
                db.commit()
                out=root/'output'
                archive_audit.safe_private_dir(out)
                with mock.patch.dict(archive_audit.TARGET_FOLDER,{'sent':'Sent Items'}):
                    report=archive_audit.compare_headers(db,'Sent',out)
                self.assertEqual(report['target_folder'],'Sent Items')
                self.assertEqual(report['target_headers'],1)
                self.assertEqual(report['classifications']['MATCH_ID_AND_RECEIVED_HEADERS'],1)
            finally:
                db.close()

    def test_mime_validator_with_different_destination_name(self):
        from unittest import mock
        import tempfile, sqlite3
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'idx.sqlite3'
            db=archive_audit.open_db(p)
            try:
                for side,folder,uid in [('source','Sent',17),('target','Sent Items',101)]:
                    db.execute('INSERT INTO folders VALUES(?,?,?,?,?)',
                               (side,folder,'3',archive_audit.digest_uids([uid]),1))
                    db.execute('INSERT INTO headers VALUES(?,?,?,?,?,?,?,?,?)',
                               (side,folder,uid,'id','strong','meta','noid',1,1234))
                db.commit()
            finally:
                db.close()
            with mock.patch.object(mime_validator,'FOLDER','Sent'), \
                 mock.patch.object(mime_validator,'TARGET_FOLDER','Sent Items'):
                plan=mime_validator.load_plan(p)
            self.assertEqual((plan['source_total'],plan['target_total']), (1,1))
            self.assertEqual(plan['cases'],[])

    def test_sent_delta_reads_different_destination_folder(self):
        from unittest import mock
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'idx.sqlite3'
            db=archive_audit.open_db(p)
            try:
                for side,folder,uid in [('source','Sent',17),('target','Sent Items',101)]:
                    db.execute('INSERT INTO folders VALUES(?,?,?,?,?)',
                               (side,folder,'3',archive_audit.digest_uids([uid]),1))
                    db.execute('INSERT INTO headers VALUES(?,?,?,?,?,?,?,?,?)',
                               (side,folder,uid,'id','strong','meta','noid',1,1234))
                db.commit()
            finally:
                db.close()
            with mock.patch.object(delta_sent,'INDEX_DB',p), \
                 mock.patch.object(delta_sent,'IMAP_FOLDER','Sent'), \
                 mock.patch.object(delta_sent,'TARGET_IMAP_FOLDER','Sent Items'):
                data=delta_sent.sent_baseline()
            self.assertEqual(data['source']['max_uid'],17)
            self.assertEqual(data['target']['max_uid'],101)

    def test_imapsync_command_uses_explicit_folder_mapping_without_network(self):
        from unittest import mock
        from types import SimpleNamespace
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            base=Path(t)
            helper=base/'helper code.py'; helper.write_text('# test\n')
            token=base/'token.txt'; token.write_text('test-token')
            migration={'user1':'sender', 'user2':'receiver'}
            pending={'range_low':18,'range_high':19}
            with mock.patch.object(delta_sent,'BASE',base), \
                 mock.patch.object(delta_sent,'CACHE',base/'cache'), \
                 mock.patch.object(delta_sent,'OAUTH_SCRIPT',helper), \
                 mock.patch.object(delta_sent,'OAUTH_WRAPPER',helper), \
                 mock.patch.object(delta_sent,'TOKEN',token), \
                 mock.patch.object(delta_sent,'IMAP_FOLDER','Sent'), \
                 mock.patch.object(delta_sent,'TARGET_IMAP_FOLDER','Sent Items'), \
                 mock.patch.object(delta_sent,'EXPECTED_HOSTS',('example.invalid','destination.example')), \
                 mock.patch.object(delta_sent.shutil,'which',return_value='/usr/bin/imapsync'), \
                 mock.patch.object(delta_sent.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as call:
                code,_=delta_sent.run_imapsync(migration,'password-test',pending)
                cmd=call.call_args.args[0]
            self.assertEqual(code,0)
            self.assertEqual(cmd[cmd.index('--f1f2')+1], 'Sent=Sent Items')
            self.assertIn("'",cmd[cmd.index('--oauthrefreshcmd2')+1])
            self.assertFalse(list(base.glob('.imap-delta-pass-*')))

    def test_public_ignorelist_allows_sources_but_blocks_private_data(self):
        import shutil, tempfile
        if not shutil.which('git'):
            self.skipTest('git not installed')
        root=Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)
            (path/'.gitignore').write_text((root/'.gitignore').read_text())
            subprocess.run(['git','init','-q',str(path)],check=True,capture_output=True)
            for allowed in ('archive_tools/archive_audit.py','README_ARCHIVE_TOOLS.md',
                            'tests/archive_tools/test_offline.py','scripts/check_archive_release.py'):
                res=subprocess.run(['git','check-ignore','-q',allowed],cwd=path)
                self.assertNotEqual(res.returncode,0,allowed)
            for blocked in ('private-mail/mail.eml','archive_tools/secret.ini',
                            'archive_tools/__pycache__/module.pyc','audit.sqlite3','config.env'):
                res=subprocess.run(['git','check-ignore','-q',blocked],cwd=path)
                self.assertEqual(res.returncode,0,blocked)
