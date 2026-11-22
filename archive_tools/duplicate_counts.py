#!/usr/bin/env python3
"""Offline 1:1 multiset analysis of message duplicates from an audit SQLite index.

Counts source/target excess using strong, metadata and Message-ID signatures."""
from __future__ import annotations
from archive_tools import config as cfg
import argparse
from collections import Counter, defaultdict
from pathlib import Path
import sqlite3

FOLDER = cfg.SOURCE_SENT_FOLDER
TARGET_FOLDER = cfg.TARGET_SENT_FOLDER
FIELDS = ('signature', 'meta_signature', 'msg_id')


def summarise_counts(src: Counter, dst: Counter) -> dict:
    keys = set(src) | set(dst)
    return {
        'matches_upper_bound': sum(min(src[k], dst[k]) for k in keys),
        'source_unpaired': sum(max(0, src[k] - dst[k]) for k in keys),
        'target_unpaired': sum(max(0, dst[k] - src[k]) for k in keys),
        'source_deficit_groups': sum(src[k] > dst[k] for k in keys),
        'target_excess_groups': sum(dst[k] > src[k] for k in keys),
    }


def load_data(conn):
    for side in ('source', 'target'):
        row = conn.execute('SELECT n_uids FROM folders WHERE side=? AND folder=?', (side, FOLDER if side == 'source' else TARGET_FOLDER)).fetchone()
        if row is None:
            raise RuntimeError(f'Kein Ordner-Index: {side}/{FOLDER}')
        stored = conn.execute('SELECT COUNT(*) FROM headers WHERE side=? AND folder=?', (side, FOLDER if side == 'source' else TARGET_FOLDER)).fetchone()[0]
        if stored != row[0]:
            raise RuntimeError(f'Index unvollstaendig: {side}/{FOLDER}: {stored}/{row[0]}')
    rows = {}
    for side in ('source', 'target'):
        rows[side] = conn.execute(
            'SELECT uid, signature, meta_signature, msg_id, size_bytes, received_count '
            'FROM headers WHERE side=? AND folder=? ORDER BY uid',
            (side, FOLDER if side == 'source' else TARGET_FOLDER),
        ).fetchall()
    return rows


def diagnostics(rows):
    src = rows['source']
    dst = rows['target']
    fields = {'signature': 1, 'meta_signature': 2, 'msg_id': 3}
    out = {'source': len(src), 'target': len(dst), 'net_difference': len(src) - len(dst), 'criteria': {}}
    for field, index in fields.items():
        # A blank Message-ID is not a meaningful identity key. Count separately.
        s = Counter(r[index] for r in src if field != 'msg_id' or r[index])
        t = Counter(r[index] for r in dst if field != 'msg_id' or r[index])
        value = summarise_counts(s, t)
        value['source_with_key'] = sum(s.values())
        value['target_with_key'] = sum(t.values())
        out['criteria'][field] = value
    out['source_without_message_id'] = sum(not row[3] for row in src)
    out['target_without_message_id'] = sum(not row[3] for row in dst)
    # The legacy classifier flags *every source row* in an underrepresented
    # strong-signature group, not only unmatched copies. The conditional matches
    # the relevant branch in audit V1.1.
    sstrong = Counter(row[1] for row in src)
    tstrong = Counter(row[1] for row in dst)
    out['legacy_strong_multiplicity_flagged_source_rows'] = sum(
        1 for r in src if r[3] and 0 < tstrong[r[1]] < sstrong[r[1]]
    )
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=cfg.AUDIT_ROOT / "header_index.sqlite3")
    args = parser.parse_args()
    db_path = args.db.expanduser().resolve(strict=True)
    conn = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True)
    try:
        rows = load_data(conn)
        data = diagnostics(rows)
    finally:
        conn.close()
    print('OFFLINE-SENT-DIAGNOSE (nur SQLite gelesen; kein IMAP-Zugriff)')
    print(f"Quelle: {data['source']:,} | target IMAP: {data['target']:,} | Netto-Fehlbestand: {data['net_difference']:+,}")
    print()
    labels = {
        'signature': 'Message-ID + Received (strenger Vergleich)',
        'meta_signature': 'Message-ID + Datum/From/To/Subject',
        'msg_id': 'Nur Message-ID (nicht eindeutig)',
    }
    for key in FIELDS:
        x = data['criteria'][key]
        print(labels[key])
        print(f"  Moegliche 1:1-Paare: {x['matches_upper_bound']:,}")
        print(f"  Quellen-Ueberhang: {x['source_unpaired']:,} in {x['source_deficit_groups']:,} Gruppen")
        print(f"  Ziel-Ueberhang:    {x['target_unpaired']:,} in {x['target_excess_groups']:,} Gruppen")
    print(f"\nV1.1-Multiplicity-Flags: {data['legacy_strong_multiplicity_flagged_source_rows']:,} Quellenzeilen")
    print('Hinweis: Ein Quellen-Ueberhang ist KEIN Beweis fuer fehlende konkrete Mails:')
    print('gleiche Message-IDs/Headers koennen mehrfach vorkommen, Header koennen veraendert sein.')
    print('Keine Nachrichten oder Datenbankeintraege wurden veraendert.')


if __name__ == '__main__':
    main()
