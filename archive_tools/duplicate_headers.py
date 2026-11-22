#!/usr/bin/env python3
"""Read-only duplicate header scanner for a configured IMAP folder.

Reports local CSV, never modifies messages."""
from archive_tools import config as cfg
import csv
import getpass
import hashlib
import imaplib
import re
import ssl
import sys
from collections import defaultdict
from datetime import datetime
from email import policy
from email.parser import BytesHeaderParser
from pathlib import Path

HOST = cfg.SOURCE_HOST
USER = cfg.SOURCE_USER
FOLDER = cfg.SENT_FOLDER
BATCH = 100
HEADER_FIELDS = '(MESSAGE-ID RECEIVED SUBJECT DATE FROM TO)'


def safe_header(msg, name):
    try:
        v = msg.get(name, '')
        return str(v).replace('\x00', '').strip() if v is not None else ''
    except Exception:
        return ''


def canonical(v):
    # Same two header *types* as imapsync's default fingerprint.
    # Minor whitespace canonicalisation may differ from imapsync internals.
    return re.sub(r'\s+', ' ', str(v)).strip()


def extract_tuples(result):
    for item in result:
        if isinstance(item, tuple) and len(item) == 2:
            meta, data = item
            uid = re.search(rb'\bUID\s+(\d+)\b', meta, re.I)
            if uid is not None and isinstance(data, bytes):
                yield int(uid.group(1)), meta, data


def audit_headers(mail, uids):
    groups = defaultdict(list)
    by_uid = {}
    p = BytesHeaderParser(policy=policy.default)
    for start in range(0, len(uids), BATCH):
        block = uids[start:start+BATCH]
        status, data = mail.uid('FETCH', ','.join(block),
                                f'(UID RFC822.SIZE BODY.PEEK[HEADER.FIELDS {HEADER_FIELDS}])')
        if status != 'OK':
            raise RuntimeError(f'Header-Abruf fehlgeschlagen ab UID {block[0]}: {status}')
        entries = list(extract_tuples(data))
        if len(entries) != len(block):
            raise RuntimeError(f'Unvollstaendiger Header-Abruf: {len(entries)}/{len(block)} ab UID {block[0]}')
        for uid, meta, raw in entries:
            msg = p.parsebytes(raw)
            mid = canonical(safe_header(msg, 'Message-ID'))
            received = tuple(canonical(x) for x in msg.get_all('Received', []))
            # imapsync identifies messages through Message-ID + Received headers.
            # Do not merge completely empty fingerprints (not a meaningful match).
            key = (mid, received) if mid or received else ('<missing>', (f'uid:{uid}',))
            size_match = re.search(rb'\bRFC822\.SIZE\s+(\d+)\b', meta, re.I)
            rec = {
                'uid': uid,
                'message_id': mid,
                'subject': safe_header(msg, 'Subject'),
                'date': safe_header(msg, 'Date'),
                'from': safe_header(msg, 'From'),
                'to': safe_header(msg, 'To'),
                'size_bytes': int(size_match.group(1)) if size_match else '',
            }
            groups[key].append(rec)
            by_uid[uid] = rec
        if (start // BATCH) % 20 == 0 or start + BATCH >= len(uids):
            print(f'Header: {min(start+BATCH,len(uids)):,}/{len(uids):,}', flush=True)
    return groups


def hash_message(mail, uid):
    status, data = mail.uid('FETCH', str(uid), '(UID BODY.PEEK[])')
    if status != 'OK':
        raise RuntimeError(f'Nachricht UID {uid} nicht abrufbar ({status})')
    found = list(extract_tuples(data))
    if len(found) != 1 or found[0][0] != uid:
        raise RuntimeError(f'Unvollstaendige Nachricht UID {uid}')
    raw = found[0][2]
    return hashlib.sha256(raw).hexdigest(), len(raw)


def main():
    if '--help' in sys.argv or '-h' in sys.argv:
        print(__doc__)
        return
    cfg.require_online()
    cfg.AUDIT_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    if cfg.AUDIT_ROOT.is_symlink():
        raise RuntimeError('Symlink-Ausgabeverzeichnis nicht erlaubt')
    import os
    os.chmod(cfg.AUDIT_ROOT, 0o700)
    # Keep generated CSV private on disk.
    import os
    os.umask(0o077)
    try:
        import certifi
    except ImportError:
        raise SystemExit('Optional dependency certifi missing; install it with pip.')
    ctx = ssl.create_default_context(cafile=certifi.where())
    pw = getpass.getpass('Quell-IMAP-Passwort: ')
    print('Verbinde mit Quell-IMAP (nur lesend) ...')
    try:
        with imaplib.IMAP4_SSL(HOST, 993, ssl_context=ctx, timeout=120) as mail:
            mail.login(USER, pw)
            pw = None
            status, info = mail.select(cfg.quote_imap_folder(FOLDER), readonly=True)
            if status != 'OK':
                raise RuntimeError('Ordner konnte nicht geoeffnet werden')
            print('Nachrichten laut SELECT:', info[0].decode())
            status, data = mail.uid('SEARCH', None, 'ALL')
            if status != 'OK':
                raise RuntimeError('IMAP UID SEARCH ALL fehlgeschlagen')
            uids = [x.decode('ascii') for x in data[0].split()]
            print('UIDs:', len(uids))
            groups = audit_headers(mail, uids)
            duplicates = [v for v in groups.values() if len(v) > 1]
            duplicates.sort(key=lambda g: min(r['uid'] for r in g))
            extras = sum(len(group) - 1 for group in duplicates)
            print(f'\nIdentifizierte Gruppen: {len(duplicates)}, zusaetzliche Kopien: {extras}')
            print('Pruefe den SHA-256 der vollstaendigen Originalnachrichten ...', flush=True)
            report = []
            equal_groups = 0
            unequal_groups = 0
            for index, group in enumerate(duplicates, 1):
                digests = set()
                for rec in group:
                    digest, read_size = hash_message(mail, rec['uid'])
                    rec['sha256'] = digest
                    rec['read_bytes'] = read_size
                    digests.add(digest)
                equal = len(digests) == 1
                equal_groups += int(equal)
                unequal_groups += int(not equal)
                status = 'BYTE_IDENTISCH' if equal else 'INHALT_UNTERSCHIEDLICH'
                for rec in group:
                    report.append({
                        'gruppe': index,
                        'bewertung': status,
                        'anzahl_kopien': len(group),
                        'zusatzkopien': len(group)-1,
                        **rec,
                    })
                print(f'{index:3}/{len(duplicates)} | {status:22} | '
                      f'{len(group)} Kopien | UIDs: '
                      f'{",".join(str(x["uid"]) for x in group)} | '
                      '(Betreff nur in privater CSV)', flush=True)
    except (imaplib.IMAP4.error, TimeoutError, OSError, RuntimeError) as exc:
        raise SystemExit(f'FEHLER: {exc}')

    out = cfg.AUDIT_ROOT / f'duplicates-{datetime.now():%Y%m%d_%H%M%S}.csv'
    fields = ['gruppe','bewertung','anzahl_kopien','zusatzkopien','uid','message_id',
              'date','from','to','subject','size_bytes','read_bytes','sha256']
    with out.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(report)
    print('\nFAZIT')
    print(f'- Quellordner: {len(uids)} Nachrichten')
    print(f'- Headergleiche Duplikatgruppen: {len(duplicates)}')
    print(f'- Zusaetzliche Kopien (Quelle): {extras}')
    print(f'- Komplett byte-identische Gruppen: {equal_groups}')
    print(f'- Inhaltlich unterschiedliche Gruppen: {unequal_groups}')
    print(f'- CSV: {out}')
    print('Keine E-Mails wurden veraendert, verschoben oder geloescht.')


if __name__ == '__main__':
    main()
