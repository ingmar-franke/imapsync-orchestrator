#!/usr/bin/env python3
"""Read-only decoded MIME comparison for duplicate IMAP entries.

Reads candidate groups from a private local CSV and writes hash-only evidence."""
from archive_tools import config as cfg
import csv
import getpass
import hashlib
import imaplib
import os
from pathlib import Path
import re
import ssl
import sys
from collections import defaultdict
from email import policy
from email.parser import BytesParser

HOST = cfg.SOURCE_HOST
USER = cfg.SOURCE_USER
FOLDER = cfg.SENT_FOLDER
DEFAULT_CSV = cfg.AUDIT_ROOT / 'duplicates.csv'
OUT_CSV = cfg.AUDIT_ROOT / 'duplicates_mime.csv'


def h(payload):
    return hashlib.sha256(payload).hexdigest()


def fetch_uid(mail, uid):
    status, data = mail.uid('FETCH', str(uid), '(UID BODY.PEEK[])')
    if status != 'OK':
        raise RuntimeError(f'FETCH fehlgeschlagen: UID {uid}')
    for item in data:
        if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes):
            if re.search(rb'\bUID\s+' + str(uid).encode() + rb'\b', item[0]):
                return item[1]
    raise RuntimeError(f'Nachricht nicht enthalten in FETCH-Antwort: UID {uid}')


def body_bytes(raw):
    m = re.search(rb'\r?\n\r?\n', raw)
    return raw[m.end():] if m else raw


def signatures(raw):
    parsed = BytesParser(policy=policy.default).parsebytes(raw)
    text_parts, attachment_parts, other_parts = [], [], []
    for part in parsed.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        filename = str(part.get_filename() or '')
        filename_hash = h(filename.encode('utf-8')) if filename else ''
        disp = part.get_content_disposition() or ''
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = str(part.get_payload() or '').encode('utf-8', errors='replace')
        item = (content_type, filename_hash, len(payload), h(payload))
        if disp == 'attachment' or filename:
            attachment_parts.append(item)
        elif content_type.startswith('text/'):
            text_parts.append(item)
        else:
            other_parts.append(item)
    return tuple(text_parts), tuple(attachment_parts), tuple(other_parts)


def main():
    if '--help' in sys.argv or '-h' in sys.argv:
        print(__doc__)
        return
    cfg.require_online()
    cfg.AUDIT_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    if cfg.AUDIT_ROOT.is_symlink():
        raise RuntimeError('Symlink-Ausgabeverzeichnis nicht erlaubt')
    os.chmod(cfg.AUDIT_ROOT, 0o700)
    os.umask(0o077)
    source = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else DEFAULT_CSV
    if not source.is_file():
        raise SystemExit(f'CSV nicht gefunden: {source}')
    try:
        import certifi
    except ImportError:
        raise SystemExit('Optional dependency certifi missing; install it with pip.')

    with source.open(encoding='utf-8-sig', newline='') as f:
        src = list(csv.DictReader(f))
    groups = defaultdict(list)
    for rec in src:
        groups[int(rec['gruppe'])].append(rec)
    candidates = {k:v for k,v in groups.items() if len({r['sha256'] for r in v}) > 1}
    print(f'SHA-abweichende Gruppen: {len(candidates)}, abgerufene Quellnachrichten: {sum(map(len, candidates.values()))}')
    ctx = ssl.create_default_context(cafile=certifi.where())
    pw = getpass.getpass('Quell-IMAP-Passwort: ')
    results = []
    with imaplib.IMAP4_SSL(HOST, 993, ssl_context=ctx, timeout=120) as imap:
        imap.login(USER, pw)
        pw = None
        status, _ = imap.select(cfg.quote_imap_folder(FOLDER), readonly=True)
        if status != 'OK':
            raise RuntimeError('Ordner nicht lesbar')
        for i, (group_id, records) in enumerate(sorted(candidates.items()), 1):
            observed = []
            for rec in records:
                uid = int(rec['uid'])
                raw = fetch_uid(imap, uid)
                txt, attachments, others = signatures(raw)
                observed.append({
                    'gruppe': group_id, 'uid': uid,
                    'hash_csv_stabil': 'JA' if h(raw) == rec['sha256'] else 'NEIN',
                    'rohdaten_sha256': h(raw), 'body_sha256': h(body_bytes(raw)),
                    'text_signature': txt, 'attachments_signature': attachments,
                    'other_signature': others, 'attachment_names': '; '.join(a[1] for a in attachments),
                    'attachment_count': len(attachments), 'text_part_count': len(txt),
                })
            def distinct(field):
                return len({str(r[field]) for r in observed})
            if distinct('body_sha256') == 1:
                status = 'NUR_HEADER_UNTERSCHIED'
            elif all(distinct(key) == 1 for key in ('text_signature', 'attachments_signature', 'other_signature')):
                status = 'GLEICHE_DEKODIERTE_MIME_INHALTE'
            else:
                diffs=[]
                if distinct('text_signature')>1: diffs.append('TEXT')
                if distinct('attachments_signature')>1: diffs.append('ANHAENGE')
                if distinct('other_signature')>1: diffs.append('SONSTIGE_MIME_TEILE')
                status='UNTERSCHIED_' + '_UND_'.join(diffs)
            if any(x['hash_csv_stabil']=='NEIN' for x in observed):
                status += '_HASH_NICHT_STABIL'
            for row in observed:
                results.append({
                    'gruppe': group_id, 'bewertung': status, 'uid': row['uid'],
                    'sha_alt_bei_nachtest_stabil': row['hash_csv_stabil'],
                    'raw_sha256': row['rohdaten_sha256'], 'body_sha256': row['body_sha256'],
                    'text_teile': row['text_part_count'], 'anhaenge': row['attachment_count'],
                    'dateinamen': row['attachment_names'],
                    'text_signatur': repr(row['text_signature']),
                    'anhang_signatur': repr(row['attachments_signature']),
                    'sonstiges_signatur': repr(row['other_signature'])
                })
            print(f'{i:2}/{len(candidates)} Gruppe {group_id}: {status}; UIDs {",".join(str(v["uid"]) for v in observed)}', flush=True)

    cols=['gruppe','bewertung','uid','sha_alt_bei_nachtest_stabil','raw_sha256',
          'body_sha256','text_teile','anhaenge','dateinamen','text_signatur','anhang_signatur','sonstiges_signatur']
    with OUT_CSV.open('w', newline='', encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=cols)
        w.writeheader()
        w.writerows(results)
    print(f'\nFertig. CSV: {OUT_CSV}')
    print('Keine E-Mails wurden veraendert oder kopiert.')

if __name__ == '__main__':
    main()
