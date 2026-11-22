#!/usr/bin/env python3
"""Read-only INBOX content spot-check of ambiguous header pairs and extra targets.

Requires a completed header-index audit; does not modify mailboxes."""
from __future__ import annotations
from archive_tools import config as cfg
import argparse
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesHeaderParser
import getpass
import hashlib
import imaplib
import json
from pathlib import Path
import re
import sqlite3
import time

OUT = cfg.AUDIT_ROOT
ROOT = cfg.MIGRATION_ROOT
FOLDER = cfg.SOURCE_INBOX_FOLDER
TARGET_FOLDER = cfg.TARGET_INBOX_FOLDER
FILENAME = 'inbox_abschlusspruefung.json'


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_counter(c: Counter) -> str:
    pairs = sorted((str(key), int(count)) for key, count in c.items())
    return sha(json.dumps(pairs, ensure_ascii=False, separators=(',', ':')).encode())


def load_plan(db_path: Path) -> dict:
    from archive_tools.inbox_header_diagnostics import audit
    if not db_path.is_file() or db_path.is_symlink():
        raise RuntimeError('SQLite-Index fehlt oder ist Symlink: ' + str(db_path))
    conn = sqlite3.connect(db_path.resolve().as_uri() + '?mode=ro', uri=True)
    try:
        report = audit(conn)
        metadata = {}
        for side in ('source', 'target'):
            result = conn.execute('SELECT uidvalidity,uid_list_sha256,n_uids FROM folders '
                                  'WHERE side=? AND folder=?', (side, FOLDER if side == 'source' else TARGET_FOLDER)).fetchone()
            if not result:
                raise RuntimeError('Folderindex fehlt: ' + side)
            metadata[side] = dict(uidvalidity=str(result[0]), uid_sha256=result[1], count=result[2])
        targets = {int(r[0]): {'size':r[1], 'has_mid':bool(r[2])} for r in conn.execute(
            'SELECT uid,size_bytes,msg_id FROM headers WHERE side=? AND folder=?', ('target',TARGET_FOLDER))}
    finally:
        conn.close()
    if report['unmatched_source_entries']:
        raise RuntimeError('Erwarteter INBOX-Abgleich (0 fehlende Quelle, 8 zusätzliche Ziele) stimmt nicht')
    pairs = []
    dest_seen = set()
    for r in report['source_without_message_id']:
        if len(r['matching_target_uids']) != 1:
            raise RuntimeError(f"Quelle UID {r['uid']}: kein eindeutiges Ziel")
        tid = int(r['matching_target_uids'][0])
        if tid in dest_seen:
            raise RuntimeError('Ein Ziel mehreren Quellen ohne Message-ID zugeordnet')
        dest_seen.add(tid)
        if tid not in targets or r['rfc822_size'] is None or targets[tid]['size'] is None:
            raise RuntimeError('Unbekannte Nachrichtengröße in sechs Prüfpaaren')
        pairs.append({'source_uid':int(r['uid']),'source_size':int(r['rfc822_size']),
                      'target_uid':tid,'target_size':int(targets[tid]['size'])})
    extras = sorted([{'uid':int(r['uid']), 'size':r['rfc822_size'],
                      'has_message_id':r['has_message_id']} for r in report['unmatched_target']],
                    key=lambda x:x['uid'])
    plan = {'folder':FOLDER, 'metadata':metadata, 'pairs':pairs, 'extra_target':extras}
    plan['digest'] = sha(json.dumps(plan, sort_keys=True, separators=(',',':')).encode())
    return plan


def safe_evidence(raw: bytes) -> dict:
    """Keine E-Mail-Texte, URLs oder Anhänge in Ergebnisdatei aufnehmen."""
    from archive_tools.mime_validator import mime_evidence
    result = mime_evidence(raw)
    result['fetched_bytes'] = len(raw)
    try:
        from archive_tools.mime_visible import fingerprint_message
        parsed = fingerprint_message(raw)
        bodies = []
        for item in parsed['bodies']:
            bodies.append({'type':item['type'], 'visible_sha256':item['visible_hash'],
                           'visible_characters':item['visible_length'],
                           'link_fingerprint':digest_counter(item['attr_hashes']),
                           'link_count':sum(item['attr_hashes'].values())})
        result['body_fingerprints'] = bodies
        result['binary_fingerprint'] = digest_counter(parsed['binary'])
        result['visible_parse_status'] = 'ok'
    except (ValueError, UnicodeError, TypeError) as exc:
        result['visible_parse_status'] = 'not_evaluable'
        result['visible_parse_issue'] = type(exc).__name__
    return result


def parse_extra_header(data, requested_uid: int, expected_size: int | None) -> dict:
    parsed = []
    for item in data or []:
        if not (isinstance(item, tuple) and len(item) == 2):
            continue
        prefix, payload = item
        if not isinstance(prefix, bytes) or not isinstance(payload, bytes):
            continue
        uid = re.search(rb'\bUID\s+(\d+)\b', prefix, flags=re.I)
        sz = re.search(rb'\bRFC822\.SIZE\s+(\d+)\b', prefix, flags=re.I)
        internal = re.search(rb'\bINTERNALDATE\s+"([^"]+)"', prefix, flags=re.I)
        if not uid or not sz or int(uid.group(1)) != requested_uid:
            raise RuntimeError(f'Unpassende UID/SIZE-Antwort für UID {requested_uid}')
        got_size = int(sz.group(1))
        if expected_size is not None and got_size != expected_size:
            raise RuntimeError(f'UID {requested_uid}: RFC822.SIZE im Index verändert')
        msg = BytesHeaderParser(policy=policy.default).parsebytes(payload)
        def field(name: str) -> str:
            try:
                return ' '.join(str(msg.get(name, '')).split())
            except Exception:
                return ''
        parsed.append({'uid': requested_uid, 'rfc822_size': got_size,
                       'internaldate':internal.group(1).decode('ascii', errors='replace') if internal else None,
                       'date':field('Date'), 'from':field('From'),
                       'to':field('To'), 'subject':field('Subject'),
                       'message_id':field('Message-ID')})
    if len(parsed) != 1:
        raise RuntimeError(f'UID {requested_uid}: {len(parsed)} Headerdatensätze statt 1')
    return parsed[0]


def classification(a: dict, b: dict) -> str:
    if a.get('status') != 'ok' or b.get('status') != 'ok':
        return 'NICHT_GEPRUEFT'
    if a['raw_sha256'] == b['raw_sha256']:
        return 'ROHDATEN_IDENTISCH'
    if a['mime_sha256'] == b['mime_sha256'] and not a['mime_fallback_parts'] and not b['mime_fallback_parts']:
        return 'MIME_NUTZDATEN_IDENTISCH'
    if (a.get('visible_parse_status') == b.get('visible_parse_status') == 'ok'
        and a.get('body_fingerprints') == b.get('body_fingerprints')
        and a.get('binary_fingerprint') == b.get('binary_fingerprint')):
        return 'SICHTTEXT_LINKS_ANHAENGE_IDENTISCH'
    return 'INHALT_ABWEICHEND_ODER_UNGEKLAERT'



def live_uid_delta(db_path: Path, side: str, expected: dict, live_uids: list[int]) -> dict:
    """Compare a current mailbox with the *historical* indexed UID set.

    Does not overwrite or rebaseline the evidence index. A newly received mail
    is recorded rather than treated as an invalidation of older UID mappings.
    """
    from archive_tools.archive_audit import digest_uids
    conn = sqlite3.connect(db_path.resolve().as_uri() + '?mode=ro', uri=True)
    try:
        old = [int(r[0]) for r in conn.execute(
            'SELECT uid FROM headers WHERE side=? AND folder=? ORDER BY uid',
            (side, FOLDER if side == 'source' else TARGET_FOLDER))]
    finally:
        conn.close()
    if len(old) != int(expected['count']) or digest_uids(old) != expected['uid_sha256']:
        raise RuntimeError(f'{side}: vorhandener SQLite-Headerindex stimmt nicht mit ursprünglichem UID-Snapshot überein')
    live = set(live_uids)
    old_set = set(old)
    added = sorted(live - old_set)
    removed = sorted(old_set - live)
    return {
        'indexed_count': len(old), 'live_count': len(live_uids),
        'added_since_index': len(added), 'missing_since_index': len(removed),
        'added_uid_examples': added[:20], 'missing_uid_examples': removed[:20],
        'uidvalidity_unchanged': True,
        'warning': ('Historical header index was NOT modified. New source messages are NOT '
                    'automatically migrated; removed indexed UIDs are a separate audit risk.')
    }


class PinnedReadOnlySession:
    """Read-only IMAP FETCH with stable UIDVALIDITY and pinned UID presence.

    The mailbox may receive new mail while the audit is running. On reconnect,
    validate the IDs needed for this *targeted* test rather than requiring
    unrelated UIDs to remain a frozen mailbox-wide snapshot.
    """
    RETRY_DELAYS = (3, 7, 15, 30, 60, 90)

    def __init__(self, opener, folder: str, side: str, uidvalidity: str, pinned_uids):
        self.opener = opener
        self.folder = folder
        self.side = side
        self.expected_uidvalidity = str(uidvalidity)
        self.pinned = set(int(uid) for uid in pinned_uids)
        self.conn = None

    def start(self):
        from archive_tools.archive_audit import select_readonly, search_uids, close_imap_quietly
        if self.conn is not None:
            raise RuntimeError('IMAP-Sitzung bereits geöffnet')
        conn = self.opener()
        try:
            count, uidvalidity = select_readonly(conn, self.folder)
            uids = search_uids(conn)
            if len(uids) != count:
                raise RuntimeError(f'{self.side}: Postfach während UID SEARCH verändert; erneut versuchen')
            if str(uidvalidity) != self.expected_uidvalidity:
                raise RuntimeError(f'{self.side}: UIDVALIDITY verändert; alte UID-Zuordnung ungültig, Prüfung gestoppt')
            missing = sorted(self.pinned - set(uids))
            if missing:
                raise RuntimeError(f'{self.side}: benötigte UID(s) nicht mehr vorhanden: {missing[:20]}; '
                                   'Prüfung sicherheitshalber gestoppt')
        except BaseException:
            close_imap_quietly(conn)
            raise
        self.conn = conn
        return count, str(uidvalidity), uids

    def uid(self, verb: str, *args):
        if verb != 'FETCH':
            raise RuntimeError('Nur IMAP UID FETCH erlaubt')
        failures = 0
        while True:
            try:
                if self.conn is None:
                    self.start()
                return self.conn.uid(verb, *args)
            except (imaplib.IMAP4.abort, OSError, EOFError) as exc:
                from archive_tools.archive_audit import close_imap_quietly
                close_imap_quietly(self.conn)
                self.conn = None
                if failures >= len(self.RETRY_DELAYS):
                    raise RuntimeError(f'{self.side}: IMAP nach mehreren Verbindungsabbrüchen nicht verfügbar') from exc
                pause = self.RETRY_DELAYS[failures]
                failures += 1
                print(f'{self.side}: IMAP-Verbindung unterbrochen; neuer Versuch {failures} '
                      f'nach {pause}s, UIDVALIDITY und Prüffall-UIDs werden erneut kontrolliert', flush=True)
                time.sleep(pause)

    def close(self):
        from archive_tools.archive_audit import close_imap_quietly
        conn, self.conn = self.conn, None
        close_imap_quietly(conn, graceful=True)


def run_online(plan: dict, out: Path, root: Path, size_limit_mib: int) -> dict:
    from archive_tools.archive_audit import (
        source_login, target_login, state_and_manifest, packet_progress, completed_migration_lock,
    )
    from archive_tools.mime_validator import verified_fetch_one
    state, rows = state_and_manifest(root)
    pstate = packet_progress(state, rows)
    if not pstate['all_packets_processed']:
        raise RuntimeError('Migrationsstatus nicht abgeschlossen')
    src_user, dest_user = state.get('user1'), state.get('user2')
    if not src_user or not dest_user:
        raise RuntimeError('Benutzer im Migrationsstatus fehlen')
    path = out / FILENAME
    progress = {'schema':1, 'plan_digest':plan['digest'], 'folder':FOLDER,
                'source':{}, 'target':{}, 'extra_target_headers':{}, 'snapshot_deltas':{}, 'errors':[]}
    if path.exists():
        if path.is_symlink():
            raise RuntimeError('Ergebnisdatei ist Symlink')
        old = json.loads(path.read_text(encoding='utf-8'))
        if old.get('plan_digest') != plan['digest'] or old.get('schema') != 1:
            raise RuntimeError('Gespeicherte Ergebnisdatei gehört zu anderem INBOX-Index')
        progress = old
    cap = size_limit_mib * 1024**2
    from archive_tools.mime_validator import private_write
    with completed_migration_lock(root, pstate):
        for side in ('source','target'):
            to_fetch = []
            for pair in plan['pairs']:
                uid = pair[side+'_uid']
                if str(uid) not in progress[side]:
                    to_fetch.append((uid, pair[side+'_size']))
            extra_needed = (side == 'target' and any(str(r['uid']) not in progress['extra_target_headers']
                                                       for r in plan['extra_target']))
            if not to_fetch and not extra_needed:
                print(side + ': bereits geprüft; Zwischenergebnis wiederverwendet')
                continue
            password = getpass.getpass('Quell-IMAP-Passwort: ') if side == 'source' else None
            opener = ((lambda: source_login(src_user, password)) if side == 'source'
                      else (lambda: target_login(dest_user)))
            expected = plan['metadata'][side]
            pinned = [pair[side+'_uid'] for pair in plan['pairs']]
            if side == 'target':
                pinned += [item['uid'] for item in plan['extra_target']]
            sess = PinnedReadOnlySession(opener, FOLDER if side == 'source' else TARGET_FOLDER, side, expected['uidvalidity'], pinned)
            try:
                count, validity, uids = sess.start()
                delta = live_uid_delta(out/'header_index.sqlite3', side, expected, uids)
                progress.setdefault('snapshot_deltas', {})[side] = delta
                private_write(path, progress)
                print(f'{side}/{FOLDER}: UIDVALIDITY unverändert, Prüffall-UIDs vorhanden; '
                      f'Index {delta["indexed_count"]:,}, aktuell {delta["live_count"]:,}, '
                      f'neu {delta["added_since_index"]}, inzwischen entfernt {delta["missing_since_index"]}')
                if delta['missing_since_index']:
                    print(f'WARNUNG: {side}: {delta["missing_since_index"]} früher indexierte UIDs '
                          f'sind nicht mehr vorhanden (Beispiele: {delta["missing_uid_examples"]}); '
                          'separater Archivstatus zu prüfen', flush=True)
                if side == 'source' and delta['added_since_index']:
                    print(f'HINWEIS: {delta["added_since_index"]} source-Nachrichten sind seit dem '
                          'Headerindex neu; diese Schlussprüfung migriert sie NICHT', flush=True)
                for uid,size in to_fetch:
                    if size > cap:
                        progress[side][str(uid)]={'status':'skipped_size', 'indexed_size':size}
                        print(f'UID {uid}: über Größenlimit; nicht geladen')
                    else:
                        got_size, raw, mismatch = verified_fetch_one(sess, uid, size)
                        evidence = safe_evidence(raw)
                        del raw
                        progress[side][str(uid)]={'status':'ok', 'uid':uid,
                           'rfc822_size':got_size, 'size_mismatch':mismatch, **evidence}
                        print(f'{side}: UID {uid} inhaltlich erfasst')
                    private_write(path, progress)
                if side == 'target':
                    for item in plan['extra_target']:
                        uid = item['uid']
                        if str(uid) in progress['extra_target_headers']:
                            continue
                        typ, response = sess.uid('FETCH', str(uid),
                           '(UID RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER.FIELDS (DATE FROM TO SUBJECT MESSAGE-ID)])')
                        if typ != 'OK':
                            raise RuntimeError('Header FETCH fehlgeschlagen: '+str(uid))
                        row = parse_extra_header(response, uid, item['size'])
                        progress['extra_target_headers'][str(uid)] = row
                        private_write(path, progress)
                        print(f'target IMAP zusätzlich UID {uid}: Header lokal erfasst (personenbezogene Felder unterdrückt)')
            finally:
                sess.close()
                password = None
    progress['completed_utc'] = datetime.now(timezone.utc).isoformat()
    private_write(path, progress)
    return progress


def print_summary(plan: dict, progress: dict) -> None:
    counts = Counter()
    print('\nINBOX: Nachrichtenpaare ohne Message-ID')
    for pair in plan['pairs']:
        a = progress['source'].get(str(pair['source_uid']), {})
        b = progress['target'].get(str(pair['target_uid']), {})
        kind = classification(a,b)
        counts[kind]+=1
        print(f"  Quelle {pair['source_uid']} -> target IMAP {pair['target_uid']}: {kind}")
    print('Zusammenfassung:', ', '.join(f'{k}={v}' for k,v in counts.items()))
    print('Zusätzliche Zieleinträge: ', len(progress['extra_target_headers']), '/', len(plan['extra_target']), 'Header erfasst')



def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--plan', action='store_true', help='offline Plan; keine Verbindung')
    ap.add_argument('--out',type=Path,default=OUT)
    ap.add_argument('--root',type=Path,default=ROOT)
    ap.add_argument('--max-size-mib',type=int, default=30)
    a=ap.parse_args()
    if not 1 <= a.max_size_mib <= 50:
        ap.error('--max-size-mib muss 1..50 sein')
    if not a.out.is_dir() or a.out.is_symlink():
        ap.error('Auditverzeichnis fehlt oder ist Symlink: '+str(a.out))
    plan = load_plan(a.out/'header_index.sqlite3')
    print(f'INBOX-SCHLUSSPRÜFUNG: {len(plan["pairs"])} Quellen-/Zielpaare ohne Message-ID und '
          f'{len(plan["extra_target"])} zusätzliche target IMAP-Header')
    print('Keine Mailänderungen; keine E-Mail-Texte oder Anhänge in der Ergebnisdatei')
    if a.plan:
        for p in plan['pairs']:
            print(f'  Quelle {p["source_uid"]} -> Ziel {p["target_uid"]}; Größen {p["source_size"]}/{p["target_size"]}')
        for ex in plan['extra_target']:
            print(f'  zusätzlich target IMAP UID {ex["uid"]}; Größe {ex["size"]}')
        return
    result=run_online(plan,a.out,a.root,a.max_size_mib)
    print_summary(plan,result)
    print('Bericht:', a.out/FILENAME)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, sqlite3.Error, ValueError) as exc:
        raise SystemExit('FEHLER: '+str(exc))
