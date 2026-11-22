#!/usr/bin/env python3
"""Offline 1:1 source/target INBOX header match with no-Message-ID handling.

Reads the audit SQLite database read-only and saves local derived evidence."""
from __future__ import annotations
from archive_tools import config as cfg
import argparse
from collections import defaultdict, deque, Counter
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import sqlite3
import sys

DEFAULT_DB = cfg.AUDIT_ROOT / "header_index.sqlite3"
DEFAULT_OUT = cfg.AUDIT_ROOT / "inbox_header_diagnostics.json"
FOLDER = cfg.SOURCE_INBOX_FOLDER
TARGET_FOLDER = cfg.TARGET_INBOX_FOLDER


def fail(s):
    raise SystemExit('FEHLER: ' + str(s))


def read_rows(conn, side):
    return [dict(zip(('uid', 'msg_id', 'signature', 'meta_signature',
                      'no_id_signature', 'received_count', 'size_bytes'), row))
            for row in conn.execute('''SELECT uid,msg_id,signature,meta_signature,
                                       no_id_signature,received_count,size_bytes
                                       FROM headers WHERE side=? AND folder=? ORDER BY uid''',
                                    (side, FOLDER if side == 'source' else TARGET_FOLDER))]


def strict_key(r):
    if not r['msg_id']:
        return ('noid', r['no_id_signature'])
    # A message with no Received lines has a less discriminating signature;
    # combine it with date/from/to/subject metadata to avoid overmatching.
    if r['received_count'] == 0:
        return ('mid+meta', r['signature'], r['meta_signature'])
    return ('mid+received', r['signature'])


def other_key(r):
    if not r['msg_id']:
        return ('noid-meta', r['no_id_signature'])
    return ('mid+meta', r['meta_signature'])


def match(rows_source, rows_target):
    target_by_key = defaultdict(deque)
    for r in rows_target:
        target_by_key[strict_key(r)].append(r)
    strict_pairs, missing_src = [], []
    for s in rows_source:
        q = target_by_key[strict_key(s)]
        if q:
            strict_pairs.append((s, q.popleft()))
        else:
            missing_src.append(s)
    leftovers = [r for q in target_by_key.values() for r in q]
    # Fallback for changes to Received-only headers, but never equate by Message-ID alone.
    fallback_by_key = defaultdict(deque)
    for r in sorted(leftovers, key=lambda x: x['uid']):
        fallback_by_key[other_key(r)].append(r)
    other_pairs, still_missing = [], []
    for s in missing_src:
        q = fallback_by_key[other_key(s)]
        if q:
            other_pairs.append((s, q.popleft()))
        else:
            still_missing.append(s)
    still_extra = sorted((r for q in fallback_by_key.values() for r in q), key=lambda r:r['uid'])
    return strict_pairs, other_pairs, still_missing, still_extra


def compact(r):
    return {'uid': r['uid'], 'has_message_id': bool(r['msg_id']),
            'received_count': r['received_count'], 'rfc822_size': r['size_bytes'],
            'signature_sha256': r['signature'], 'metadata_sha256': r['meta_signature']}


def audit(conn):
    expected = {}
    for side in ('source', 'target'):
        row = conn.execute("SELECT n_uids, uidvalidity, uid_list_sha256 FROM folders WHERE side=? AND folder=?",
                           (side, FOLDER if side == 'source' else TARGET_FOLDER)).fetchone()
        if row is None:
            fail(f'{side}/{FOLDER}: keine Folder-Metadaten im Index')
        expected[side] = int(row[0])
    source = read_rows(conn, 'source')
    target = read_rows(conn, 'target')
    for side, rows in (('source', source), ('target', target)):
        if len(rows) != expected[side] or len({r['uid'] for r in rows}) != len(rows):
            fail(f'{side}/{FOLDER}: Index unvollständig oder UIDs mehrfach; nichts bewertet')

    strict, meta, missing, extra = match(source, target)
    target_noid = defaultdict(list)
    for r in target:
        if not r['msg_id']:
            target_noid[r['no_id_signature']].append(r)
    src_noids = []
    for r in source:
        if not r['msg_id']:
            others = target_noid.get(r['no_id_signature'], [])
            src_noids.append({**compact(r), 'matching_target_uids': [x['uid'] for x in others],
                               'matching_target_sizes': [x['size_bytes'] for x in others],
                               'only_header_match': True})

    report = {
        'schema': 1, 'folder': FOLDER, 'read_only': True,
        'source_entries': len(source), 'target_entries': len(target),
        'strict_header_pairs': len(strict), 'fallback_header_pairs': len(meta),
        'unmatched_source_entries': len(missing),
        'unmatched_target_entries': len(extra),
        'source_without_message_id': src_noids,
        'unmatched_source': [compact(r) for r in missing],
        'unmatched_target': [compact(r) for r in extra],
        'warning': 'Headergleichheit ist kein Inhalts- oder 1:1 Archivbeweis; historische UID-Lücken müssen separat geprüft werden.'
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=DEFAULT_DB)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    a = parser.parse_args(argv)
    if not a.db.is_file():
        fail(f'Datenbank nicht vorhanden: {a.db}')
    db = sqlite3.connect(a.db.resolve().as_uri() + '?mode=ro', uri=True)
    try:
        report = audit(db)
    finally:
        db.close()
    print('OFFLINE-INBOX-RESTPRUEFUNG (nur SQLite gelesen; kein IMAP-Zugriff)')
    print(f"Quelle: {report['source_entries']:,} | target IMAP: {report['target_entries']:,}")
    print(f"1:1 Header-Paare (streng): {report['strict_header_pairs']:,}")
    print(f"1:1 Header-Paare (Fallback): {report['fallback_header_pairs']:,}")
    print(f"Quell-Einträge ohne Message-ID: {len(report['source_without_message_id'])}")
    for item in report['source_without_message_id']:
        print(f"  Quelle UID {item['uid']} -> Ziel UID(s) {item['matching_target_uids'] or 'KEINE'}")
    print(f"Nicht zugeordnete Quell-Einträge: {report['unmatched_source_entries']}")
    for item in report['unmatched_source'][:20]:
        print(f"  Offene Quelle UID {item['uid']}")
    print(f"Nicht zugeordnete Ziel-Einträge: {report['unmatched_target_entries']}")
    for item in report['unmatched_target'][:30]:
        print(f"  Zusätzliches Ziel UID {item['uid']} (RFC822.SIZE {item['rfc822_size']})")
    # JSON is private metadata; output atomically, with user-only permissions.
    a.out.parent.mkdir(parents=True, exist_ok=True)
    if a.out.exists() and a.out.is_symlink():
        fail('Ausgabepfad ist Symlink; verweigert')
    temp = a.out.with_name(a.out.name + '.tmp.' + str(os.getpid()))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            f.write('\n')
        os.replace(temp, a.out)
    finally:
        if temp.exists(): temp.unlink()
    print('Bericht:', a.out)


if __name__ == '__main__':
    main()
