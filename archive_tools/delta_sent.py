#!/usr/bin/env python3
"""Incremental SENT migration built on a fully indexed header-audit baseline.

Operates independently of delta_inbox; never backfills historical duplicates.
Only explicit sync may APPEND via imapsync."""
from __future__ import annotations
from archive_tools import config as cfg

import argparse
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import sqlite3
import subprocess
import sys
import tempfile

ROOT = cfg.MIGRATION_ROOT
BASE = cfg.AUDIT_ROOT / "delta"
STATE = BASE / "delta_sent.json"
CACHE = BASE / "cache-sent"
IMAP_FOLDER = cfg.SOURCE_SENT_FOLDER
TARGET_IMAP_FOLDER = cfg.TARGET_SENT_FOLDER
INDEX_DB = cfg.AUDIT_ROOT / "header_index.sqlite3"
BATCH_LIMIT = 100
OAUTH_SCRIPT = cfg.OAUTH_HELPER
OAUTH_WRAPPER = cfg.OAUTH_WRAPPER
TOKEN = cfg.OAUTH_TOKEN
# Must match the already audited original migration. No new accounts guessed here.
EXPECTED_HOSTS = (cfg.SOURCE_HOST, cfg.TARGET_HOST)
EXPECTED_USERS = (cfg.SOURCE_USER, cfg.TARGET_USER)
FIELDS = "(MESSAGE-ID RECEIVED DATE FROM TO SUBJECT)"


def auditlib():
    # Same project directory as the established, user-tested audit script.
    import archive_tools.archive_audit as mod
    return mod


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def ensure_dir(path: Path):
    if path.is_symlink():
        raise RuntimeError("Symlink als Arbeitsverzeichnis unzulässig: " + str(path))
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def write_json(path: Path, value: dict):
    ensure_dir(path.parent)
    if path.is_symlink():
        raise RuntimeError("Statusdatei ist ein Symlink")
    fd, temp = tempfile.mkstemp(prefix=".delta-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def load_json(path: Path) -> dict | None:
    if path.is_symlink():
        raise RuntimeError("Statusdatei ist ein Symlink")
    if not path.exists():
        return None
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise RuntimeError("Ungültige Delta-Statusdatei")
    return result


def original_migration():
    a = auditlib()
    cfg.require_online()
    migration, rows = a.state_and_manifest(ROOT)
    progress = a.packet_progress(migration, rows)
    if not progress['all_packets_processed'] or progress['checkpointed_present'] + len(progress['known_missing_source_uids']) != progress['planned']:
        raise RuntimeError("Alte Migration nicht vollständig abgeschlossen; kein Delta-Transfer")
    if tuple(migration.get(key) for key in ('source', 'target')) != EXPECTED_HOSTS:
        raise RuntimeError("Abweichende IMAP-Server im ursprünglichen Migrationsstatus")
    if tuple(migration.get(key) for key in ('user1', 'user2')) != EXPECTED_USERS:
        raise RuntimeError("Abweichende Konten im ursprünglichen Migrationsstatus")
    if not isinstance(migration.get('snapshot_max_uid'), int) or migration['snapshot_max_uid'] <= 0:
        raise RuntimeError("Ursprünglicher maximaler UID-Wert ist ungültig")
    return migration


def sent_baseline():
    """Auditierte SENT-UID-Snapshots strikt LESEND aus separater SQLite-Datei.

    Bei unerwarteten Summen oder unvollstaendigem Index keine automatische
    Nachmigration. Bestehenden Index niemals aktualisieren oder ersetzen.
    """
    if not INDEX_DB.is_file() or INDEX_DB.is_symlink():
        raise RuntimeError('Audit-Headerindex fehlt oder ist ein Symlink; kein SENT-Delta')
    db = sqlite3.connect(INDEX_DB.as_uri() + '?mode=ro', uri=True)
    try:
        db.execute('PRAGMA query_only=ON')
        rows = {}
        for side in ('source', 'target'):
            rec = db.execute(
                'SELECT uidvalidity, uid_list_sha256, n_uids FROM folders '
                'WHERE side=? AND folder=?', (side, IMAP_FOLDER if side == 'source' else TARGET_IMAP_FOLDER)
            ).fetchone()
            if not rec or not isinstance(rec[2], int) or rec[2] < 1:
                raise RuntimeError(f'{side}: SENT-Audit-Snapshot fehlt/hat unerwartete Anzahl')
            count = rec[2]
            indexed, highwater = db.execute(
                'SELECT COUNT(*), MAX(uid) FROM headers WHERE side=? AND folder=?',
                (side, IMAP_FOLDER if side == 'source' else TARGET_IMAP_FOLDER)
            ).fetchone()
            if indexed != count or type(highwater) is not int or highwater < 1:
                raise RuntimeError(f'{side}: SENT-Headerindex unvollstaendig')
            uidvalidity, uid_digest, n_uids = rec
            if not str(uidvalidity).isdigit() or not re.fullmatch(r'[0-9a-f]{64}', str(uid_digest)):
                raise RuntimeError(f'{side}: SENT-Snapshot-Kennung ungueltig')
            rows[side] = {
                'uidvalidity': str(uidvalidity), 'uid_digest': uid_digest,
                'count': count, 'max_uid': highwater,
            }
        return rows
    finally:
        db.close()


def validated_state(migration, baseline):
    s = load_json(STATE)
    base = baseline['source']['max_uid']
    basis_digest = hashlib.sha256(json.dumps(baseline, sort_keys=True).encode()).hexdigest()
    expected = {'schema': 1, 'scope': IMAP_FOLDER,
                'source_host': EXPECTED_HOSTS[0], 'target_host': EXPECTED_HOSTS[1],
                'source_uidvalidity': baseline['source']['uidvalidity'],
                'target_uidvalidity': baseline['target']['uidvalidity'],
                'historical_manifest_sha256': migration['manifest_sha256'],
                'audited_sent_baseline_sha256': basis_digest,
                'initial_uid_highwater': base, 'target_folder': TARGET_IMAP_FOLDER}
    if s is None:
        return {**expected, 'completed_upto_uid': base, 'pending': None, 'history': []}
    for key, val in expected.items():
        if s.get(key) != val:
            raise RuntimeError('SENT-Delta-Status nicht mit auditiertem Bestand kompatibel: ' + key)
    watermark = s.get('completed_upto_uid')
    if type(watermark) is not int or watermark < base:
        raise RuntimeError('Ungueltiger SENT-Delta-Highwatermark')
    if not isinstance(s.get('history'), list):
        raise RuntimeError('Ungueltige SENT-Delta-Historie')
    if s.get('pending') is not None and not isinstance(s['pending'], dict):
        raise RuntimeError('Ungueltiger ausstehender SENT-Transfer')
    return s


@contextmanager
def exclusive_lock():
    if not ROOT.is_dir():
        raise RuntimeError('Alter Migrationsordner fehlt')
    lockpath = ROOT / 'run.lock'
    if lockpath.is_symlink():
        raise RuntimeError('run.lock ist ein Symlink')
    with lockpath.open('a+') as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Ein alter/anderer Migrationsprozess läuft; nicht parallel starten') from exc
        yield


def open_source(password, migration, baseline):
    a = auditlib()
    conn = a.source_login(migration['user1'], password)
    try:
        n, validity = a.select_readonly(conn, IMAP_FOLDER)
        if str(validity) != baseline['source']['uidvalidity']:
            raise RuntimeError('Quell-UIDVALIDITY wurde geändert; kein automatischer Abgleich')
        uids = a.search_uids(conn)
        if len(uids) != n:
            raise RuntimeError('Quellordner während Aufnahme geändert; erneut versuchen')
        return conn, uids
    except BaseException:
        a.close_imap_quietly(conn)
        raise


def open_target(migration, baseline):
    a = auditlib()
    conn = a.target_login(migration['user2'])
    try:
        n, validity = a.select_readonly(conn, TARGET_IMAP_FOLDER)
        if str(validity) != baseline['target']['uidvalidity']:
            raise RuntimeError('Ziel-UIDVALIDITY wurde geändert; kein automatischer Abgleich')
        uids = a.search_uids(conn)
        if len(uids) != n:
            raise RuntimeError('Zielordner während Aufnahme geändert; erneut versuchen')
        return conn, uids
    except BaseException:
        a.close_imap_quietly(conn)
        raise


def fetch_headers(conn, uids: list[int]) -> dict[int, dict]:
    a = auditlib()
    result = {}
    for i in range(0, len(uids), 25):
        group = uids[i:i + 25]
        if not group:
            continue
        typ, dat = conn.uid('FETCH', ','.join(map(str, group)),
                            f'(UID RFC822.SIZE BODY.PEEK[HEADER.FIELDS {FIELDS}])')
        if typ != 'OK':
            raise RuntimeError('Headerabruf fehlgeschlagen')
        parsed = a.headers_from_fetch(dat)
        if set(parsed) != set(group):
            raise RuntimeError('Headerabruf unvollständig, UID-Liste hat sich geändert')
        result.update(parsed)
    return result


def match_header_pairs(source: dict[int, dict], target: dict[int, dict]):
    """Conservative 1:1 matching. Never match solely on Message-ID or on size."""
    indexed = defaultdict(deque)
    for uid in sorted(target):
        r = target[uid]
        key = ('mid+meta', r['meta_signature']) if r['msg_id'] else ('noid', r['no_id_signature'])
        indexed[key].append(uid)
    paired, missing = [], []
    for uid in sorted(source):
        r = source[uid]
        key = ('mid+meta', r['meta_signature']) if r['msg_id'] else ('noid', r['no_id_signature'])
        if indexed[key]:
            paired.append([uid, indexed[key].popleft()])
        else:
            missing.append(uid)
    return paired, missing


def preexisting_sent_headers(selected: dict[int, dict], live_new_target: dict[int, dict]):
    """Stop on ambiguous matches in existing SENT target, do not infer content identity.

    Previously indexed source copies are excluded by the audited high-watermark,
    so this concerns exclusively NEW source messages. Header collisions are not proof
    of identical MIME content; require manual handling instead of silently
    confirming a new mail that imapsync might deduplicate.
    """
    if not selected:
        return []
    out = []
    db = sqlite3.connect(INDEX_DB.as_uri() + '?mode=ro', uri=True)
    try:
        db.execute('PRAGMA query_only=ON')
        for src_uid, src in selected.items():
            if src['msg_id']:
                # One Message-ID can denote distinct content, so even one
                # existing identity match requires a manual decision.
                sql = ('SELECT uid FROM headers WHERE side=? AND folder=? '
                       'AND msg_id=? ORDER BY uid LIMIT 3')
                candidates = db.execute(sql, ('target', TARGET_IMAP_FOLDER, src['msg_id'])).fetchall()
                target_matches = [uid for (uid,) in candidates]
                target_matches.extend(uid for uid, r in live_new_target.items()
                                      if r['msg_id'] == src['msg_id'])
            else:
                sql = ('SELECT uid FROM headers WHERE side=? AND folder=? '
                       "AND msg_id='' AND no_id_signature=? ORDER BY uid LIMIT 3")
                candidates = db.execute(sql, ('target', TARGET_IMAP_FOLDER,
                                               src['no_id_signature'])).fetchall()
                target_matches = [uid for (uid,) in candidates]
                target_matches.extend(uid for uid, r in live_new_target.items()
                                      if not r['msg_id'] and
                                      r['no_id_signature'] == src['no_id_signature'])
            if target_matches:
                out.append({'source_uid': src_uid, 'target_uid_examples': sorted(set(target_matches))[:5]})
    finally:
        db.close()
    return out


def source_header_collisions(selected: dict[int, dict]):
    groups = defaultdict(list)
    for uid, row in selected.items():
        key = ('mid', row['msg_id']) if row['msg_id'] else ('noid', row['no_id_signature'])
        groups[key].append(uid)
    return [sorted(uids) for uids in groups.values() if len(uids) > 1]


def preview(migration, baseline, state, password):
    a = auditlib()
    src = dst = None
    try:
        src, source_uids = open_source(password, migration, baseline)
        dst, target_uids = open_target(migration, baseline)
        if state.get('pending'):
            return dict(pending=True, source_count=len(source_uids), target_count=len(target_uids),
                        pending_uids=state['pending']['uids'], selected=[], watermark=state['completed_upto_uid'])
        watermark = state['completed_upto_uid']
        new = [x for x in source_uids if x > watermark]
        selected = new[:BATCH_LIMIT]
        selected_headers = fetch_headers(src, selected)
        extra_target = [uid for uid in target_uids if uid > baseline['target']['max_uid']]
        if len(extra_target) > 5000:
            raise RuntimeError('Unerwartet viele neue Ziel-UIDs seit SENT-Audit; manuell prüfen')
        live_new_headers = fetch_headers(dst, extra_target) if selected else {}
        conflicts = preexisting_sent_headers(selected_headers, live_new_headers)
        return {'pending': False, 'watermark': watermark, 'selected': selected,
                'remaining_after_batch': max(0, len(new) - len(selected)),
                'source_count': len(source_uids), 'target_count': len(target_uids),
                'target_max_uid': target_uids[-1] if target_uids else 0,
                'selected_headers': selected_headers, 'header_collisions': conflicts,
                'source_collisions': source_header_collisions(selected_headers)}
    finally:
        a.close_imap_quietly(src, graceful=True)
        a.close_imap_quietly(dst, graceful=True)


def run_imapsync(migration, pwd, pending):
    ensure_dir(BASE)
    ensure_dir(CACHE)
    if not shutil.which('imapsync'):
        raise RuntimeError('imapsync ist nicht auf diesem System installiert')
    if not (OAUTH_SCRIPT.is_file() and OAUTH_WRAPPER.is_file() and TOKEN.is_file()):
        raise RuntimeError('target IMAP OAuth-Helfer/Token oder V2.11-Skript fehlt im konfigurierten Verzeichnis')
    if not pwd or '\n' in pwd or '\r' in pwd:
        raise RuntimeError('Ungültiges Quell-IMAP-Passwort')
    fd, passpath = tempfile.mkstemp(prefix='.imap-delta-pass-', dir=BASE)
    logpath = BASE / ('imapsync-sent-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f') + '.log')
    import certifi
    ca_file = certifi.where()
    command = ['imapsync', '--host1', EXPECTED_HOSTS[0], '--ssl1',
               '--sslargs1', 'SSL_verify_mode=1', '--sslargs1', f'SSL_ca_file={ca_file}',
               '--user1', migration['user1'], '--passfile1', passpath,
               '--host2', EXPECTED_HOSTS[1], '--ssl2',
               '--sslargs2', 'SSL_verify_mode=1', '--sslargs2', f'SSL_ca_file={ca_file}',
               '--user2', migration['user2'], '--oauthaccesstoken2', str(TOKEN),
               '--oauthrefreshcmd2', f'{shlex.quote(sys.executable)} {shlex.quote(str(OAUTH_WRAPPER))} oauth-refresh',
               '--folder', IMAP_FOLDER,
               *(['--f1f2', IMAP_FOLDER + '=' + TARGET_IMAP_FOLDER] if IMAP_FOLDER != TARGET_IMAP_FOLDER else []),
               '--noautomap',
               '--search1', f'UID {pending["range_low"]}:{pending["range_high"]}',
               '--useuid', '--tmpdir', str(CACHE),
               '--nofoldersizes', '--nofoldersizesatend', '--noreleasecheck',
               '--pidfile', str(BASE / 'imapsync-sent.pid'), '--pidfilelocking', '--nolog']
    os.fchmod(fd, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as passfile:
            passfile.write(pwd)
            passfile.write('\n')
            passfile.flush()
            os.fsync(passfile.fileno())
        with logpath.open('xb') as log:
            os.fchmod(log.fileno(), 0o600)
            outcome = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=2*3600)
        return outcome.returncode, str(logpath)
    finally:
        try:
            os.unlink(passpath)
        except FileNotFoundError:
            pass


def reconcile(migration, baseline, state, password):
    """Read-only; only target UIDs after start of pending transfer qualify as copied."""
    a = auditlib()
    pending = state['pending']
    if not pending:
        raise RuntimeError('Kein ausstehender Transfer')
    src = dst = None
    try:
        src, src_live = open_source(password, migration, baseline)
        dst, dst_live = open_target(migration, baseline)
        expected_uids = list(map(int, pending['uids']))
        missing_src = sorted(set(expected_uids) - set(src_live))
        if missing_src:
            return {'verified': False, 'reason': 'source_uids_no_longer_in_inbox',
                    'missing_source_uids': missing_src}
        src_headers = fetch_headers(src, expected_uids)
        for uid in expected_uids:
            old = pending['source_header_keys'].get(str(uid))
            h = src_headers[uid]
            current = [h['msg_id'], h['meta_signature'], h['no_id_signature']]
            if current != old:
                return {'verified': False, 'reason': 'source_header_changed', 'uid': uid}
        dest_new = [x for x in dst_live if x > int(pending['target_uid_before'])]
        if len(dest_new) > 5000:
            return {'verified': False, 'reason': 'too_many_new_target_messages',
                    'new_target_count': len(dest_new)}
        target_headers = fetch_headers(dst, dest_new)
        pairs, missing = match_header_pairs(src_headers, target_headers)
        return {'verified': not missing, 'source_checked': len(expected_uids),
                'target_new_checked': len(dest_new), 'header_pairs': pairs,
                'unmatched_source_uids': missing, 'source_live_count': len(src_live),
                'target_live_count': len(dst_live),
                'note': 'Nur Header 1:1 geprüft; kein vollständiger MIME- oder Rohdatenbeweis.'}
    finally:
        a.close_imap_quietly(src, graceful=True)
        a.close_imap_quietly(dst, graceful=True)


def finish(state, match):
    p = state['pending']
    if not match['verified']:
        return
    row = {'verified_utc': utcnow(), 'range': [p['range_low'], p['range_high']],
           'source_uids': p['uids'], 'paired_target_uids': match['header_pairs'],
           'imapsync_exit_code': p.get('imapsync_exit_code'),
           'header_verification': True, 'note': match['note']}
    state['history'].append(row)
    state['completed_upto_uid'] = p['range_high']
    state['pending'] = None
    write_json(STATE, state)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'sync', 'check', 'status'])
    args = parser.parse_args(argv)
    os.umask(0o077)
    ensure_dir(BASE)
    migration = original_migration()
    baseline = sent_baseline()
    state = validated_state(migration, baseline)
    if args.action == 'status':
        print('Archiv: Sent, nur UID >', state['initial_uid_highwater'])
        print('Zuletzt erfolgreich geprüft bis UID:', state['completed_upto_uid'])
        print('Erfolgreiche Delta-Läufe:', len(state['history']))
        print('Ungeklärter Übertragungsversuch:', 'JA' if state['pending'] else 'nein')
        if state['pending']:
            print('Ausstehende UIDs:', state['pending']['uids'])
        print('Historische Mehrfachexemplare: nicht Gegenstand dieses Delta-Abgleichs')
        return
    with exclusive_lock():
        password = getpass.getpass('Quell-IMAP-Passwort: ')
        if args.action == 'check':
            if not state['pending']:
                print('Kein offener Transfer.'); return
            result = reconcile(migration, baseline, state, password)
            print('PRÜFUNG:', json.dumps(result, ensure_ascii=False))
            if result['verified']:
                finish(state, result)
                print('Headerzuordnung bestätigt; Highwatermark aktualisiert.')
            else:
                print('NICHT bestätigt. Kein erneuter Transfer; Status und Cache erhalten.')
            return
        plan = preview(migration, baseline, state, password)
        if plan['pending']:
            print('OFFENER TRANSFER:', plan['pending_uids'])
            print('Kein automatischer Wiederholungsversuch. Zuerst `check` ausführen.')
            return
        print('Quelle Sent:', plan['source_count'], '| target IMAP Sent:', plan['target_count'])
        print('Bereits geprüft bis UID:', plan['watermark'])
        print('Neue aktuelle source-UIDs:', plan['selected'] or 'keine')
        print('Weitere UIDs über Batchlimit:', plan['remaining_after_batch'])
        if plan['source_collisions']:
            print('ACHTUNG: Mehrfachexemplare innerhalb des neuen source-Batches:', plan['source_collisions'])
        if plan['header_collisions']:
            print('ACHTUNG: Neue source-Header entsprechen bereits vorhandenen target IMAP-Nachrichten:')
            for item in plan['header_collisions']:
                print('  Quelle UID', item['source_uid'], '-> Ziel UID(s)', item['target_uid_examples'])
        if args.action == 'plan':
            print('NUR LESEND. Keine Nachrichten übertragen.'); return
        if not plan['selected']:
            print('Keine neuen Nachrichten; kein Kopiervorgang.'); return
        if plan['header_collisions'] or plan['source_collisions']:
            print('STOP: Header-Dublette(n) erkannt. Kein automatischer Teiltransfer.'); return
        if not shutil.which('imapsync') or not OAUTH_WRAPPER.is_file() or not TOKEN.is_file():
            raise RuntimeError('imapsync/OAuth-Voraussetzungen fehlen; kein Zustand geschrieben')
        selected = plan['selected']
        headers = plan['selected_headers']
        pending = {'uids': selected, 'range_low': plan['watermark'] + 1,
                   'range_high': selected[-1],
                   'target_uid_before': plan['target_max_uid'],
                   'source_header_keys': {str(uid): [headers[uid]['msg_id'],
                                     headers[uid]['meta_signature'], headers[uid]['no_id_signature']]
                                          for uid in selected},
                   'created_utc': utcnow(), 'stage': 'before_imapsync'}
        state['pending'] = pending
        write_json(STATE, state)
        print('Übertrage UID-Bereich', f'{pending["range_low"]}:{pending["range_high"]}',
              'mit eigenem, dauerhaftem imapsync-Cache ...', flush=True)
        try:
            code, logpath = run_imapsync(migration, password, pending)
        except BaseException as exc:
            print('IMAPSYNC ABGEBROCHEN:', type(exc).__name__, '- kein automatischer Retry.')
            print('Status/Cache bleiben erhalten. `check` prüft lesend, was angekommen ist.')
            raise
        pending['imapsync_exit_code'] = code
        pending['logpath'] = logpath
        pending['stage'] = 'after_imapsync'
        write_json(STATE, state)
        print('imapsync Rückgabecode:', code, '| privates Log:', logpath)
        if code != 0:
            print('Kopiervorgang nicht eindeutig bestätigt; NICHT erneut starten. Erst `check`.')
            return
        result = reconcile(migration, baseline, state, password)
        print('Headerprüfung:', len(result.get('header_pairs', [])), '/', len(selected),
              '| ungeklärt:', result.get('unmatched_source_uids', []))
        if result['verified']:
            finish(state, result)
            print('ERFOLG: Neue Nachrichten 1:1 per Header zugeordnet. Status:', STATE)
        else:
            print('NICHT bestätigt. Kein Retry oder Checkpoint; `check` zur Nachprüfung verwenden.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nUnterbrochen. Kein automatischer Retry. `check` kann den Zielstand prüfen.', file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print('FEHLER:', str(exc), file=sys.stderr)
        sys.exit(1)
