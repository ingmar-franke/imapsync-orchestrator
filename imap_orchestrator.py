#!/usr/bin/env python3
"""Restartable IMAP inbox migration with UID checkpoints and memory monitoring.

Prototype for macOS and Microsoft 365 OAuth authentication. The OAuth refresh
helper is supplied separately. Test with non-production mailboxes first.
The final audit checks counts and UID stability, not full message contents.
"""
from __future__ import annotations

import argparse
import bisect
from collections import deque
import concurrent.futures
import fcntl
import getpass
import hashlib
import imaplib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time

import certifi

HOME = Path.home()
ROOT = Path(os.getenv('IMAP_WORK_DIR', str(HOME / '.local' / 'state' / 'imapsync-orchestrator'))).expanduser()
MANIFEST = ROOT / 'uid_pakete.tsv'
STATE = ROOT / 'migration.json'
LOGS = ROOT / 'logs'
SRC = os.getenv('IMAP_SOURCE_HOST', '').strip()
DST = os.getenv('IMAP_TARGET_HOST', '').strip()
USER1 = os.getenv('IMAP_SOURCE_USER', '').strip()
USER2 = os.getenv('IMAP_TARGET_USER', '').strip()
PYTHON = Path(os.getenv('IMAP_PYTHON', sys.executable)).expanduser()
OAUTH = Path(os.getenv('IMAP_OAUTH_REFRESH_SCRIPT', str(HOME / '.config' / 'imapsync-orchestrator' / 'oauth_refresh.py'))).expanduser()
TOKEN = Path(os.getenv('IMAP_ACCESS_TOKEN_FILE', str(HOME / '.local' / 'share' / 'imapsync-orchestrator' / 'access_token.txt'))).expanduser()
PACKET = 2_000
PROBE_COUNT = 200  # Teil des naechsten regulaeren Pakets; keine Testnachrichten
PROBE_RSS_LIMIT_MIB = 5_500  # beide imapsync-Prozesse zusammen; Abbruch bei Ueberschreitung
SAFE_CHUNK = 200              # maximum source messages per resumable sub-batch
SAFE_RSS_LIMIT_MIB = 5_500    # conservative cap; resume-smart uses system telemetry
SMART_COMBINED_RSS_LIMIT_MIB = 8_192  # absoluter Notstopp auch bei gruener Druckanzeige
SMART_SINGLE_RSS_LIMIT_MIB = 6_400    # pro Prozess (auch beim seriellen Fallback)
SMART_SAMPLE_SECONDS = 10          # macOS-Statusabfrage; RSS weiterhin alle 2 s
SMART_SWAP_WINDOW_SECONDS = 90
SMART_SWAP_GROWTH_MIB = 384        # binnen 90 s, erst bei 2 Warnmessungen
SMART_SWAP_GROWTH_HARD_MIB = 1024  # binnen 90 s, sofortiger Stopp
SMART_START_AVAILABLE_PCT = 30     # zum Start von 2 Workern (binaerer Druck muss normal sein)
SMART_WARN_AVAILABLE_PCT = 25      # erst nach 3 Messungen hintereinander
SMART_CRITICAL_AVAILABLE_PCT = 15  # sofortiger Sicherheitsstopp
SMART_MONITOR_ERRORS = 2          # 2 fehlende Systemmessungen => sicherer Rueckfall
HEARTBEAT_SECONDS = 45  # Statusanzeige im Hauptterminal, kein weiterer IMAP-Zugriff
POLL_SECONDS = 2
RETRIES = 3
TIMEOUT_SECONDS = 6 * 3600
SCHEMA = 2
LOCK = threading.RLock()
imaplib._MAXLINE = 20_000_000


def validate_config() -> None:
    """Require explicit account configuration and keep runtime data outside the code tree."""
    required = ('IMAP_SOURCE_HOST', 'IMAP_TARGET_HOST', 'IMAP_SOURCE_USER',
                'IMAP_TARGET_USER', 'IMAP_OAUTH_REFRESH_SCRIPT', 'IMAP_ACCESS_TOKEN_FILE')
    missing = [key for key in required if not os.getenv(key, '').strip()]
    if missing:
        raise RuntimeError('Konfiguration fehlt: ' + ', '.join(missing))
    code_root = Path(__file__).resolve().parent
    for label, path in (('IMAP_WORK_DIR', ROOT), ('IMAP_ACCESS_TOKEN_FILE', TOKEN)):
        if path.resolve().is_relative_to(code_root):
            raise RuntimeError(label + ' muss ausserhalb des Quellcode-Verzeichnisses liegen')
    if not PYTHON.is_file() or not OAUTH.is_file():
        raise RuntimeError('Python-Interpreter oder OAuth-Refresh-Helfer fehlt')


def secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir() or path.is_symlink():
        raise RuntimeError(f'Verzeichnis nicht sicher: {path}')
    os.chmod(path, 0o700)


def atomic_write(path: Path, value: str) -> None:
    secure_dir(path.parent)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.temp-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(value)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def save_state(state: dict) -> None:
    atomic_write(STATE, json.dumps(state, ensure_ascii=False, indent=2) + '\n')


def load_state() -> dict:
    if not STATE.exists():
        raise RuntimeError('Kein Zustand: zuerst `plan` ausfuehren')
    state = json.loads(STATE.read_text(encoding='utf-8'))
    if state.get('schema') != SCHEMA:
        raise RuntimeError('Status-Schema geaendert. Keine automatische Migration!')
    if ((state.get('source'), state.get('user1'), state.get('target'), state.get('user2'))
            != (SRC, USER1, DST, USER2)):
        raise RuntimeError('Zustand gehoert zu anderen Konten/Servern')
    if state['manifest_sha256'] != hashlib.sha256(MANIFEST.read_bytes()).hexdigest():
        raise RuntimeError('UID-Manifest nachtraeglich geaendert!')
    return state


def batches() -> list[tuple[int, int, int]]:
    rows = []
    for line in MANIFEST.read_text(encoding='utf-8').splitlines():
        a, b, n = [int(x) for x in line.split('\t')]
        if a <= 0 or b < a or n < 1 or n > PACKET:
            raise RuntimeError(f'Fehlerhafter UID-Bereich: {line}')
        if rows and rows[-1][1] >= a:
            raise RuntimeError('UID-Bereiche ueberschneiden sich')
        rows.append((a, b, n))
    if not rows:
        raise RuntimeError('Leeres UID-Manifest')
    return rows


def sslcontext():
    return ssl.create_default_context(cafile=certifi.where())


def source(password: str):
    m = imaplib.IMAP4_SSL(SRC, 993, ssl_context=sslcontext(), timeout=120)
    try:
        m.login(USER1, password)
        typ, _ = m.select('INBOX', readonly=True)
        if typ != 'OK':
            raise RuntimeError('Quell-INBOX nicht lesbar')
        return m
    except BaseException:
        m.logout()
        raise


def refresh_oauth():
    secure_dir(ROOT)
    with (ROOT / 'oauth.lock').open('w') as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        p = subprocess.run([str(PYTHON), str(OAUTH), '--refresh'],
                           capture_output=True, text=True, timeout=180)
        if p.returncode:
            raise RuntimeError(f'OAuth-Refresh fehlgeschlagen (Exit {p.returncode}); Helferausgabe aus Datenschutzgruenden unterdrueckt')


def target():
    refresh_oauth()
    token = TOKEN.read_text(encoding='utf-8').strip()
    m = imaplib.IMAP4_SSL(DST, 993, ssl_context=sslcontext(), timeout=120)
    try:
        m.authenticate('XOAUTH2', lambda _: f'user={USER2}\x01auth=Bearer {token}\x01\x01'.encode())
        typ, _ = m.select('INBOX', readonly=True)
        if typ != 'OK':
            raise RuntimeError('M365-INBOX nicht lesbar')
        return m
    except BaseException:
        m.logout()
        raise


def uidvalidity(m) -> str:
    typ, vals = m.response('UIDVALIDITY')
    if typ != 'UIDVALIDITY' or not vals or not vals[0]:
        raise RuntimeError('UIDVALIDITY nicht ermittelbar')
    return vals[0].decode(errors='replace')


def count(m) -> int:
    typ, data = m.status('INBOX', '(MESSAGES)')
    if typ != 'OK' or not data:
        raise RuntimeError('IMAP STATUS fehlgeschlagen')
    match = re.search(rb'MESSAGES\s+(\d+)', data[0])
    if not match:
        raise RuntimeError('IMAP STATUS-Antwort unlesbar')
    return int(match.group(1))


def source_uids(m) -> list[int]:
    typ, data = m.uid('SEARCH', None, 'ALL')
    if typ != 'OK' or not data:
        raise RuntimeError('UID SEARCH ALL fehlgeschlagen')
    ids = [int(v) for v in (data[0] or b'').split()]
    if ids != sorted(set(ids)):
        raise RuntimeError('UIDs nicht streng aufsteigend/eindeutig')
    return ids


def digest_uids(uid_list: list[int]) -> str:
    h = hashlib.sha256()
    for uid in uid_list:
        h.update(f'{uid}\n'.encode('ascii'))
    return h.hexdigest()


def split_uids(ids: list[int]) -> list[tuple[int, int, int]]:
    return [(part[0], part[-1], len(part))
            for pos in range(0, len(ids), PACKET)
            if (part := ids[pos:pos + PACKET])]


def split_point(n: int) -> int:
    return (n + 1) // 2


def lane_for(index: int, n_batches: int) -> int:
    return 0 if index < split_point(n_batches) else 1


def verify_identity(password: str, state: dict):
    a = source(password)
    try:
        va = uidvalidity(a)
    finally:
        a.logout()
    b = target()
    try:
        vb = uidvalidity(b)
    finally:
        b.logout()
    if (va, vb) != (state['uidvalidity1'], state['uidvalidity2']):
        raise RuntimeError('UIDVALIDITY geaendert: Alte UID-Zuordnung nicht mehr gueltig!')


def print_prereqs():
    if not shutil.which('imapsync'):
        raise RuntimeError('imapsync fehlt im PATH; Homebrew /opt/homebrew/bin pruefen')
    if not PYTHON.exists() or not OAUTH.exists():
        raise RuntimeError('Python-Interpreter oder OAuth-Refresh-Helfer fehlt')
    result = subprocess.run(['imapsync', '--version'], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('imapsync --version fehlgeschlagen')
    print('imapsync:', (result.stdout or result.stderr).strip()[:100])
    secure_dir(ROOT)
    free = shutil.disk_usage(ROOT).free
    print(f'Freier lokaler Speicher: {free/1024**3:.1f} GiB')
    if free < 2 * 1024**3:
        raise RuntimeError('Weniger als 2 GiB frei. Nicht starten')


def do_doctor(password):
    print_prereqs()
    a = source(password)
    try:
        src_count, src_validity = count(a), uidvalidity(a)
    finally:
        a.logout()
    b = target()
    try:
        dst_count, dst_validity = count(b), uidvalidity(b)
    finally:
        b.logout()
    print(f'Quell-INBOX: {src_count} | M365-INBOX: {dst_count}')
    print(f'UIDVALIDITY Quelle: {src_validity} | Ziel: {dst_validity}')
    if STATE.exists():
        s = load_state()
        if (src_validity, dst_validity) != (s['uidvalidity1'], s['uidvalidity2']):
            raise RuntimeError('UIDVALIDITY passt nicht zum Status')
        print('Migration bereits vorbereitet. Vorhandenen Zustand beibehalten!')
    elif dst_count:
        raise RuntimeError('Ziel nicht leer, ohne Migrationsstatus. Nicht mit leerem Cache starten!')
    else:
        print('STARTVORAUSSETZUNGEN ERFUELLT (ohne Aenderung an den Postfaechern).')


def do_plan(password):
    print_prereqs()
    if STATE.exists():
        state = load_state()
        verify_identity(password, state)
        print(f'Vorhandener Plan: {state["snapshot_count"]} Nachrichten, {len(batches())} Pakete.')
        return
    a = source(password)
    try:
        src_n, va = count(a), uidvalidity(a)
        ids = source_uids(a)
    finally:
        a.logout()
    if len(ids) != src_n:
        raise RuntimeError('Quellbestand waehrend Aufnahme veraendert. Bitte `plan` wiederholen.')
    if not ids:
        raise RuntimeError('Quelle enthaelt keine Nachrichten')
    b = target()
    try:
        dest_n, vb = count(b), uidvalidity(b)
    finally:
        b.logout()
    if dest_n:
        raise RuntimeError(f'Ziel-INBOX ist nicht leer ({dest_n}). Ohne Cache/Statusdatei nicht beginnen!')
    rows = split_uids(ids)
    atomic_write(MANIFEST, ''.join(f'{x}\t{y}\t{n}\n' for x, y, n in rows))
    s = dict(schema=SCHEMA, source=SRC, user1=USER1, target=DST, user2=USER2,
             uidvalidity1=va, uidvalidity2=vb, source_uid_sha256=digest_uids(ids),
             snapshot_count=len(ids), snapshot_max_uid=ids[-1], initial_target_count=0,
             manifest_sha256=hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
             completed=[], attempts={}, results={}, in_progress={}, pilot_checked=False,
             parallel_tested=False)
    save_state(s)
    print(f'PLAN OK: {len(ids)} Nachrichten in {len(rows)} Paketen mit max. {PACKET} Mails.')
    print(f'Erstes Paket: UID {rows[0][0]}:{rows[0][1]} | {rows[0][2]} Mails')
    print(f'Zustand: {STATE}')


def parse_metrics(text: str) -> dict:
    def read(regex, cast=int):
        found = re.findall(regex, text, flags=re.MULTILINE)
        return cast(found[-1]) if found else None
    return dict(
        selected=read(r'Host1: folder \[INBOX\] selected\s+(\d+)\s+messages'),
        missing=read(r'Messages found in host1 not in host2\s*:\s*(\d+)'),
        errors=read(r'Detected\s+(\d+)\s+errors'),
        transferred=read(r'Messages transferred\s*:\s*(\d+)'),
        would_transfer=read(r'Messages transferred\s*:\s*0\s*\(could be\s+(\d+)'),
        skipped=read(r'Messages skipped\s*:\s*(\d+)'),
        ram_end_mib=read(r'Memory consumption at the end\s*:\s*([\d.]+)', float),
        return_value=read(r'Exiting with return value\s+(\d+)'),
    )


def command_for(indices: list[int], rows, lane: int, password_file: Path, *, dry: bool=False, uid_range=None):
    if not indices or any(lane_for(i, len(rows)) != lane for i in indices):
        raise RuntimeError('Paket einem falschen Worker zugewiesen')
    if indices != list(range(indices[0], indices[-1] + 1)):
        raise RuntimeError('Paketgruppe ist nicht zusammenhaengend')
    cache_dir = ROOT / f'cache-worker{lane + 1}'
    secure_dir(cache_dir)
    command = [
        'imapsync', '--host1', SRC, '--ssl1',
        '--sslargs1', 'SSL_verify_mode=1', '--sslargs1', f'SSL_ca_file={certifi.where()}',
        '--user1', USER1, '--passfile1', str(password_file),
        '--host2', DST, '--ssl2',
        '--sslargs2', 'SSL_verify_mode=1', '--sslargs2', f'SSL_ca_file={certifi.where()}',
        '--user2', USER2, '--oauthaccesstoken2', str(TOKEN),
        '--oauthrefreshcmd2', f'{shlex.quote(str(PYTHON))} {shlex.quote(str(Path(__file__).resolve()))} oauth-refresh',
        '--folder', 'INBOX', '--noautomap',
        '--search1', f'UID {uid_range[0]}:{uid_range[1]}' if uid_range else f'UID {rows[indices[0]][0]}:{rows[indices[-1]][1]}',
        '--useuid', '--tmpdir', str(cache_dir),
        '--nofoldersizes', '--nofoldersizesatend', '--noreleasecheck',
        '--pidfile', str(ROOT / f'worker{lane + 1}.pid'), '--pidfilelocking', '--nolog',
    ]
    if dry:
        command.append('--dry')
    return command


def rss_mib(pid: int) -> float | None:
    try:
        p = subprocess.run(['ps', '-o', 'rss=', '-p', str(pid)],
                           capture_output=True, text=True, timeout=5)
        if not p.returncode and p.stdout.strip():
            return int(p.stdout.strip().split()[0]) / 1024
    except (ValueError, OSError, subprocess.TimeoutExpired):
        pass
    return None


def _sysctl(name: str) -> str | None:
    """macOS-Kernelwert, ohne `memory_pressure` selbst aufzurufen.

    `memory_pressure -p/-l` wuerde aktiv Speicher belegen; niemals verwenden.
    """
    try:
        p = subprocess.run(['sysctl', '-n', name], capture_output=True,
                           text=True, timeout=4)
        return p.stdout.strip() if p.returncode == 0 and p.stdout.strip() else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def parse_swap_used_mib(output: str | None) -> float | None:
    if not output:
        return None
    match = re.search(r'\bused\s*=\s*([\d.,]+)\s*([KMGTP])(?:i?B)?\b', output, re.I)
    if not match:
        return None
    number = float(match.group(1).replace(',', '.'))
    return number * {'K': 1/1024, 'M': 1, 'G': 1024, 'T': 1024**2, 'P': 1024**3}[match.group(2).upper()]


def mac_memory_sample() -> dict:
    """Echte Kernel-Messwerte; keine Vermutung aus 'freiem' RAM."""
    level_text = _sysctl('kern.memorystatus_vm_pressure_level')
    pct_text = _sysctl('kern.memorystatus_level')
    swap_text = _sysctl('vm.swapusage')
    try:
        raw_level = int(level_text) if level_text is not None else None
    except ValueError:
        raw_level = None
    # Je nach API/OS kann 0 oder 1 fuer normal stehen.
    level = raw_level if raw_level in (0, 1, 2, 4) else None
    try:
        pct = int(pct_text) if pct_text is not None else None
    except ValueError:
        pct = None
    if pct is not None and not 0 <= pct <= 100:
        pct = None
    return {'pressure': level, 'available_pct': pct,
            'swap_used_mib': parse_swap_used_mib(swap_text),
            'monotonic': time.monotonic()}


def describe_memory(sample: dict) -> str:
    levels = {0:'normal', 1:'normal', 2:'WARNUNG', 4:'KRITISCH'}
    p = levels.get(sample.get('pressure'), 'unbekannt')
    a = sample.get('available_pct')
    s = sample.get('swap_used_mib')
    return (f'Druck={p}, Kernel-Reserve={a if a is not None else "?"}%, '
            f'Swap-belegt={s:.0f} MiB' if s is not None else
            f'Druck={p}, Kernel-Reserve={a if a is not None else "?"}%, Swap=unbekannt')


def can_start_two(sample: dict) -> tuple[bool,str]:
    """Ohne messbare Systemreserve kein zweiter Worker (fail closed)."""
    if sample.get('swap_used_mib') is None:
        return False, 'Swap-Telemetrie nicht verfuegbar'
    level, pct = sample.get('pressure'), sample.get('available_pct')
    if level is None:
        return False, 'macOS-Speicherdruck nicht ermittelbar'
    if level not in (0, 1):
        return False, 'Speicherdruck bereits erhoeht'
    if pct is None:
        return False, 'Kernel-Speicherreserve nicht ermittelbar'
    if pct < SMART_START_AVAILABLE_PCT:
        return False, f'Kernel-Speicherreserve nur {pct}%'
    return True, 'Speicherreserve fuer vorsichtigen Zwei-Worker-Versuch ausreichend'


class SmartMemoryGuard:
    """System-Druck + Swap-Trend + absolute Prozesskappung.

    Shared per Lauf zwischen Worker-Threads. Ein kurzer Ausschlag beendet
    nicht sofort die Migration, deutliche Notlage aber schon. Das Guard
    kann auf allen Plattformen mit injiziertem `sample_fn` getestet werden.
    """
    def __init__(self, workers: int, sample_fn=None, clock=None):
        self.workers = workers
        self.sample_fn = sample_fn or mac_memory_sample
        self.clock = clock or time.monotonic
        self.lock = threading.RLock()
        self.last_sample_time = None
        self.last_sample = None
        self.swap_history = deque()
        self.warn_counts = {'pressure':0,'available':0,'swap':0,'unreadable':0}
        self.last_delta_mib = 0.0

    def _sample(self, now):
        sample = self.sample_fn()
        self.last_sample = sample
        self.last_sample_time = now
        level = sample.get('pressure')
        pct = sample.get('available_pct')
        swap = sample.get('swap_used_mib')
        known = level is not None and pct is not None and swap is not None
        self.warn_counts['unreadable'] = 0 if known else self.warn_counts['unreadable'] + 1
        self.warn_counts['pressure'] = (self.warn_counts['pressure'] + 1 if level == 2 else 0)
        self.warn_counts['available'] = (self.warn_counts['available'] + 1 if pct is not None and pct < SMART_WARN_AVAILABLE_PCT else 0)
        if swap is not None:
            self.swap_history.append((now, swap))
            while len(self.swap_history) > 1 and now - self.swap_history[0][0] > SMART_SWAP_WINDOW_SECONDS:
                self.swap_history.popleft()
            # Es zaehlt NUR die Zunahme, nicht der bereits genutzte Swap.
            self.last_delta_mib = max(0.0, swap - self.swap_history[0][1])
            self.warn_counts['swap'] = (self.warn_counts['swap'] + 1 if
                                        self.last_delta_mib >= SMART_SWAP_GROWTH_MIB else 0)
        else:
            self.last_delta_mib = 0.0
            self.warn_counts['swap'] = 0
        return sample

    def check(self, pid: int, rss: float | None) -> tuple[str,dict|None,float]:
        """Returns (stop_reason, current_sample, combined_rss)."""
        with self.lock:
            with LOCK:
                RUNNING_RSS_MIB[pid] = rss or 0.0
                combined = sum(RUNNING_RSS_MIB.values())
            if rss is not None and rss > SMART_SINGLE_RSS_LIMIT_MIB:
                return f'Einzelprozess-RSS {rss:.0f} MiB > {SMART_SINGLE_RSS_LIMIT_MIB} MiB', self.last_sample, combined
            if combined > SMART_COMBINED_RSS_LIMIT_MIB:
                return f'Gesamt-RSS {combined:.0f} MiB > {SMART_COMBINED_RSS_LIMIT_MIB} MiB', self.last_sample, combined
            now = self.clock()
            if self.last_sample_time is None or now - self.last_sample_time >= SMART_SAMPLE_SECONDS:
                try:
                    self._sample(now)
                except Exception:
                    self.last_sample_time = now
                    self.warn_counts['unreadable'] += 1
                    self.last_sample = None
            sample = self.last_sample
            if self.workers < 2:
                # Seriell fortsetzen, aber nicht blind weiter bei akuter Notlage.
                if sample and (sample.get('pressure') == 4 or
                               (sample.get('available_pct') is not None and
                                sample['available_pct'] < SMART_CRITICAL_AVAILABLE_PCT)):
                    return 'Kritischer System-Speicherdruck auch bei einem Worker', sample, combined
                if self.warn_counts['pressure'] >= 6:
                    return 'Speicherdruck seit mindestens einer Minute erhoeht (seriell)', sample, combined
                if self.warn_counts['available'] >= 5:
                    return 'Wenig Kernel-Speicherreserve auch im seriellen Modus', sample, combined
                if self.warn_counts['swap'] >= 3:
                    return f'Swap waechst weiterhin rasch (+{self.last_delta_mib:.0f} MiB/90s) im seriellen Modus', sample, combined
                if self.warn_counts['unreadable'] >= SMART_MONITOR_ERRORS:
                    return 'Keine verlaesslichen macOS-Messwerte (seriell)', sample, combined
                return '', sample, combined
            if self.warn_counts['unreadable'] >= SMART_MONITOR_ERRORS:
                return 'Systemspeicher-Telemetrie wiederholt nicht verfuegbar', sample, combined
            if not sample:
                return '', sample, combined
            level, pct = sample.get('pressure'), sample.get('available_pct')
            if level == 4:
                return 'Mac-Speicherdruck KRITISCH', sample, combined
            if pct is not None and pct < SMART_CRITICAL_AVAILABLE_PCT:
                return f'Kernel-Speicherreserve nur {pct}%', sample, combined
            if self.last_delta_mib >= SMART_SWAP_GROWTH_HARD_MIB:
                return f'Swap-Zunahme +{self.last_delta_mib:.0f} MiB in 90s', sample, combined
            if self.warn_counts['pressure'] >= 2:
                return 'Anhaltender macOS-Speicherdruck WARNUNG', sample, combined
            if self.warn_counts['available'] >= 3:
                return f'Anhaltend wenig Kernel-Speicherreserve ({pct}%)', sample, combined
            if self.warn_counts['swap'] >= 2:
                return f'Anhaltend starker Swap-Anstieg (+{self.last_delta_mib:.0f} MiB/90s)', sample, combined
            return '', sample, combined


def format_elapsed(seconds: float) -> str:
    total = max(0, int(seconds))
    return f'{total // 3600:02d}:{(total // 60) % 60:02d}:{total % 60:02d}'


class LogProgress:
    """Liest nur neue Logbytes. Rein informativ, beeinflusst keinen Transfer."""
    def __init__(self, logfile: Path):
        self.logfile = logfile
        self.offset = 0
        self.fragment = b''
        self.copied = 0
        self.last_change = time.monotonic()

    def sample(self) -> tuple[int, int]:
        try:
            with self.logfile.open('rb') as f:
                f.seek(self.offset)
                chunk = f.read()
                self.offset = f.tell()
        except OSError:
            return 0, self.offset
        if chunk:
            self.last_change = time.monotonic()
            data = self.fragment + chunk
            lines = data.split(b'\n')
            self.fragment = lines.pop()
            # imapsync gibt erfolgreiche Kopien als 'msg INBOX/... copied to ...' aus.
            for line in lines:
                if re.search(rb'\bmsg\s+INBOX/\d+\b.*\bcopied to\s+INBOX/', line):
                    self.copied += 1
        return len(chunk), self.offset


# Nur waehrend des produktiven Zwei-Worker-Probes belegt.
RUNNING_RSS_MIB: dict[int, float] = {}

def execute(command: list[str], logfile: Path, timeout=TIMEOUT_SECONDS,
            *, label: str = '', expected: int | None = None,
            combined_rss_limit: int | None = None,
            stop_event: threading.Event | None = None,
            memory_guard: SmartMemoryGuard | None = None) -> tuple[int, float | None, float]:
    start = time.monotonic()
    peak = None
    progress = LogProgress(logfile)
    last_heartbeat = start
    unreadable_rss = 0
    with logfile.open('wb') as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        if label:
            print(f'[{time.strftime("%H:%M:%S")}] START {label} | '
                  f'imapsync PID {proc.pid} | Fortschritt alle {HEARTBEAT_SECONDS}s', flush=True)
        try:
            while proc.poll() is None:
                if stop_event is not None and stop_event.is_set():
                    raise RuntimeError('Ein paralleler Worker ist ausgefallen; laufenden Transfer kontrolliert stoppen')
                usage = rss_mib(proc.pid)
                if usage is not None:
                    unreadable_rss = 0
                    peak = max(peak or 0, usage)
                elif combined_rss_limit is not None:
                    unreadable_rss += 1
                    if unreadable_rss >= 10:
                        raise RuntimeError('RAM-Überwachung 10 Abfragen in Folge nicht möglich; Sicherheitsstopp')
                if memory_guard is not None:
                    if usage is None:
                        unreadable_rss += 1
                        if unreadable_rss >= 10:
                            raise MemoryError('RAM-Sicherheitsabbruch: Prozess-RSS nicht messbar')
                    reason, sample, combined = memory_guard.check(proc.pid, usage)
                    if reason:
                        raise MemoryError('RAM-Sicherheitsabbruch: ' + reason +
                                          '. Cache und Paketplan bleiben erhalten.')
                elif combined_rss_limit is not None:
                    with LOCK:
                        RUNNING_RSS_MIB[proc.pid] = usage or 0.0
                        combined = sum(RUNNING_RSS_MIB.values())
                    if combined > combined_rss_limit:
                        raise MemoryError(f'RAM-Sicherheitsabbruch: parallele imapsync-Prozesse '
                                          f'{combined:.0f} MiB > {combined_rss_limit} MiB. '
                                          'Cache und Paketplan bleiben erhalten.')
                now = time.monotonic()
                if now - start > timeout:
                    raise subprocess.TimeoutExpired('imapsync', timeout)
                if label and now - last_heartbeat >= HEARTBEAT_SECONDS:
                    delta, length = progress.sample()
                    stillness = now - progress.last_change
                    count_text = (f'{progress.copied}/{expected} Kopien im Log' if expected is not None
                                  else f'{progress.copied} Kopien im Log')
                    ram_text = f'{usage:.0f} MiB' if usage is not None else 'unbekannt'
                    note = (' | ACHTUNG: seit >3 min keine neue Logausgabe; '
                            'Prozess lebt, Datenfortschritt unklar'
                            if stillness > 180 else '')
                    system_text = ''
                    if memory_guard is not None and memory_guard.last_sample is not None:
                        system_text = (f' | System {describe_memory(memory_guard.last_sample)}'
                                       f' | Swap-Delta90s +{memory_guard.last_delta_mib:.0f} MiB')
                    print(f'[{time.strftime("%H:%M:%S")}] AKTIV {label} | '
                          f'PID {proc.pid} | Laufzeit {format_elapsed(now-start)} | '
                          f'{count_text} | Log {length/1024:.0f} KiB '
                          f'(+{delta/1024:.0f} KiB seit letzter Meldung) | '
                          f'RAM {ram_text}{system_text}{note}', flush=True)
                    last_heartbeat = now
                time.sleep(POLL_SECONDS)
            rc = proc.wait()
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=20)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                proc.wait()
            with LOCK:
                RUNNING_RSS_MIB.pop(proc.pid, None)
            raise
    with LOCK:
        RUNNING_RSS_MIB.pop(proc.pid, None)
    if label:
        # Finalen Logzuwachs fuer die Anzeigenstatistik aufnehmen.
        progress.sample()
        print(f'[{time.strftime("%H:%M:%S")}] ENDE {label} | '
              f'PID {proc.pid} | Exit {rc} | Laufzeit '
              f'{format_elapsed(time.monotonic()-start)} | '
              f'{progress.copied} Kopien im Log', flush=True)
    return rc, peak, time.monotonic() - start


def execute_group(ids, lane, rows, pwfile, *, dry=False,
                  uid_range=None, expected_override=None, log_suffix='',
                  combined_rss_limit=None, stop_event=None, memory_guard=None):
    expected = expected_override if expected_override is not None else sum(rows[i][2] for i in ids)
    start_id, end_id = ids[0]+1, ids[-1]+1
    last = None
    for trial in range(1, RETRIES + 1):
        if stop_event is not None and stop_event.is_set():
            raise RuntimeError('Parallelmigration gestoppt; kein weiterer Retry')
        log = LOGS / f'p{start_id:04d}-{end_id:04d}-w{lane+1}{log_suffix}-try{trial}{"-dry" if dry else ""}.log'
        cmd = command_for(ids, rows, lane, pwfile, dry=dry, uid_range=uid_range)
        kind = 'PRUEFUNG' if dry else 'TRANSFER'
        effective = uid_range or (rows[ids[0]][0], rows[ids[-1]][1])
        label = (f'{kind} Worker {lane+1}, Paket {start_id}-{end_id}{log_suffix}, '
                 f'Versuch {trial}/{RETRIES}, UID {effective[0]}:{effective[1]}')
        rc, peak, seconds = execute(cmd, log, label=label, expected=expected,
                                    combined_rss_limit=combined_rss_limit,
                                    stop_event=stop_event, memory_guard=memory_guard)
        stats = parse_metrics(log.read_text(errors='replace'))
        stats.update(returncode=rc, peak_rss_mib=round(peak, 1) if peak else None,
                     duration_seconds=round(seconds, 1), log=str(log), expected=expected)
        valid = (rc == 0 and stats['return_value'] == 0 and stats['errors'] == 0
                 and stats['selected'] == expected and stats['missing'] == 0)
        if dry:
            valid = (valid and stats['would_transfer'] in (None, 0)
                     and stats['transferred'] == 0 and stats['skipped'] == expected)
        else:
            valid = valid and stats['transferred'] is not None and stats['skipped'] is not None
            valid = valid and stats['transferred'] + stats['skipped'] == expected
        last = stats
        print(f'Paket {start_id}–{end_id} Worker {lane+1}, Versuch {trial}: '
              f'{"OK" if valid else "FEHLER"} | transferiert={stats["transferred"]}, '
              f'uebersprungen={stats["skipped"]}, RSS-peak={stats["peak_rss_mib"]} MiB | {log}', flush=True)
        if valid:
            return True, stats, trial
        if trial < RETRIES:
            time.sleep(45)
    return False, last, RETRIES


def grouped_pending(pending, lane, rows, bundle):
    selected = sorted(i for i in pending if lane_for(i, len(rows)) == lane)
    groups, run = [], []
    for index in selected:
        if run and (index != run[-1]+1 or len(run) >= bundle):
            groups.append(run)
            run = []
        run.append(index)
    if run:
        groups.append(run)
    return groups


def guard_cache_before_resume(state: dict, rows, *, target_messages: int | None = None):
    """Ohne UID-Cache kann ein unterbrochenes APPEND doppelt kopiert werden.

    Die Existenzpruefung erkennt einen geloeschten Cache, nicht jede partielle
    Korruption. Ein veraenderter Cache kann zu doppelten Kopien fuehren.
    """
    done = set(state['completed'])
    touched = set(done) | {int(i) for i, n in state['attempts'].items() if n > 0}
    touched.update(i for group in state.get('in_progress', {}).values() for i in group)
    for lane in (0, 1):
        had_work = any(lane_for(i, len(rows)) == lane for i in touched)
        if had_work:
            cache = ROOT / f'cache-worker{lane + 1}' / 'imapsync_cache'
            if not cache.is_dir() or not any(p.is_file() for p in cache.rglob('*')):
                raise RuntimeError(f'Worker{lane+1}: bisheriger UID-Cache fehlt. NICHT erneut kopieren!')
    if not touched and target_messages:
        # Moeglicher Abbruch nach APPEND, vor dem Schreiben des Zustands.
        caches_exist = any((ROOT / f'cache-worker{lane+1}' / 'imapsync_cache').is_dir()
                           and any(p.is_file() for p in
                                   (ROOT / f'cache-worker{lane+1}' / 'imapsync_cache').rglob('*'))
                           for lane in (0,1))
        if not caches_exist:
            raise RuntimeError('Ziel nicht mehr leer, aber kein UID-Cache/Status vorhanden!')


def observed_ram_mib(state: dict) -> float | None:
    # Der hoehere Wert aus RSS-Abtastung und imapsync-Endspeicherwert.
    values = []
    for result in state.get('results', {}).values():
        for key in ('peak_rss_mib', 'ram_end_mib'):
            if isinstance(result.get(key), (int, float)):
                values.append(float(result[key]))
    return max(values) if values else None


def run_selected(password, mode, workers=1, bundle=1):
    state = load_state()
    rows = batches()
    if state['snapshot_count'] != sum(r[2] for r in rows):
        raise RuntimeError('Manifest-Anzahl passt nicht zum Snapshot')
    verify_identity(password, state)
    if not state['completed'] and not state['attempts']:
        t = target()
        try: now_target = count(t)
        finally: t.logout()
    else:
        now_target = None
    guard_cache_before_resume(state, rows, target_messages=now_target)
    if mode in ('parallel-test', 'run') and 0 not in state['completed']:
        raise RuntimeError('Pilot zuerst ausfuehren')
    if mode == 'parallel-test' and not state['pilot_checked']:
        raise RuntimeError('Zuerst `pilot-check` ausfuehren')
    if mode == 'run' and workers == 2 and not state['parallel_tested']:
        raise RuntimeError('Vor 2 Workern zuerst `parallel-test` ausfuehren')
    if bundle > 1 and mode == 'run' and not state['parallel_tested']:
        raise RuntimeError('Vor gebuendelten Paketen zuerst `parallel-test` ausfuehren')
    peak = observed_ram_mib(state)
    if mode == 'parallel-test' or (mode == 'run' and workers == 2):
        if peak is None or peak > 2_000:
            raise RuntimeError(f'Paralleler Lauf aus RAM-Sicherheitsgruenden gesperrt '
                               f'(bisherige Spitze: {peak} MiB; Grenze: 2000 MiB). '
                               'Seriell mit --workers 1 fortfahren.')
    if mode == 'run' and bundle > 1 and (peak is None or peak > 1_000):
        raise RuntimeError(f'Buendelung aus RAM-Sicherheitsgruenden gesperrt '
                           f'(bisherige Spitze: {peak} MiB; Grenze: 1000 MiB). '
                           'Ohne --bundle starten.')
    completed = set(state['completed'])
    pending = [i for i in range(len(rows)) if i not in completed]
    if mode == 'pilot':
        if 0 in completed:
            print('Pilot bereits abgeschlossen. `pilot-check` ausfuehren.')
            return
        wanted = [[0], []]
    elif mode == 'parallel-test':
        wanted = [[next((i for i in pending if lane_for(i, len(rows)) == l), None)] for l in (0,1)]
        if any(x[0] is None for x in wanted):
            raise RuntimeError('Kein offenes Testpaket pro Worker vorhanden')
    else:
        wanted = [pending, pending]
    secure_dir(LOGS)
    passfd, passpath = tempfile.mkstemp(prefix='.pass-', dir=ROOT)
    os.fchmod(passfd, 0o600)
    try:
        with os.fdopen(passfd, 'w') as f:
            f.write(password + '\n')
        pwfile = Path(passpath)
        stop = threading.Event()
        def lane(l):
            if mode in ('pilot','parallel-test'):
                jobs = [wanted[l]] if wanted[l] else []
            else:
                jobs = grouped_pending(set(wanted[l]), l, rows, bundle)
            for indices in jobs:
                if stop.is_set():
                    break
                try:
                    with LOCK:
                        state.setdefault('in_progress', {})[str(l)] = indices
                        save_state(state)
                    ok, stats, attempts = execute_group(indices, l, rows, pwfile)
                    with LOCK:
                        for i in indices:
                            state['attempts'][str(i)] = state['attempts'].get(str(i), 0) + attempts
                        if ok:
                            for i in indices:
                                if i not in state['completed']:
                                    state['completed'].append(i)
                                state['results'][str(i)] = stats
                            state['completed'].sort()
                        state['in_progress'][str(l)] = []
                        save_state(state)
                    if not ok:
                        raise RuntimeError(f'Paket {indices[0]+1}–{indices[-1]+1}: {stats["log"]}')
                except BaseException:
                    stop.set()
                    raise
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            if mode == 'pilot':
                pool.submit(lane, 0).result()
            elif workers == 1:
                pool.submit(lane, 0).result()
                pool.submit(lane, 1).result()
            else:
                futures = [pool.submit(lane, l) for l in (0,1)]
                errors = []
                for future in futures:
                    try: future.result()
                    except Exception as e: errors.append(str(e))
                if errors:
                    raise RuntimeError(' | '.join(errors))
    finally:
        os.unlink(passpath)
    if mode == 'parallel-test':
        state['parallel_tested'] = True
        save_state(state)
        print('Parallel-Test abgeschlossen: beide Worker-Pakete erfolgreich.')
    elif mode == 'run':
        print(f'Erledigt: {len(state["completed"])}/{len(rows)} Pakete. `audit` ausfuehren.')


def do_parallel_probe(password):
    """Produktiver Kurztest: pro Worker nur die ersten 200 UIDs eines offenen Pakets.

    Der Plan bleibt unveraendert, Pakete bleiben offen. Derselbe Cache wird spaeter
    beim Vollpaket wiederverwendet; bereits zugeordnete UIDs werden uebersprungen.
    """
    state = load_state()
    rows = batches()
    verify_identity(password, state)
    guard_cache_before_resume(state, rows)
    if 0 not in state['completed'] or not state.get('pilot_checked'):
        raise RuntimeError('Pilot und `pilot-check` muessen erfolgreich sein')
    if state.get('parallel_tested'):
        print('Der volle Paralleltest wurde bereits abgeschlossen; Kurzprobe entfaellt.')
        return
    # Den bestehenden Pilot-RSS-Wert nicht als Voraussetzung verwenden:
    # je Worker nur 200 statt 2000 Nachrichten. Die Summe der aktuellen RSS-
    # Werte wird jedoch laufend ueberwacht und ggf. der Test abgebrochen.
    indices = []
    for lane in (0, 1):
        n = next((i for i in range(len(rows)) if i not in state['completed']
                  and lane_for(i, len(rows)) == lane), None)
        if n is None:
            raise RuntimeError(f'Worker {lane+1}: kein offenes Paket vorhanden')
        indices.append(n)
    a = source(password)
    try:
        if uidvalidity(a) != state['uidvalidity1']:
            raise RuntimeError('Quelle UIDVALIDITY geaendert')
        subranges = []
        for idx in indices:
            start, stop, count_expected = rows[idx]
            typ, data = a.uid('SEARCH', None, 'UID', f'{start}:{stop}')
            if typ != 'OK' or not data:
                raise RuntimeError('UID-Auswahl fehlgeschlagen')
            uids = [int(v) for v in data[0].split()]
            if len(uids) != count_expected:
                raise RuntimeError(f'Paket {idx+1}: Quellbestand veraendert '
                                   f'({len(uids)} statt {count_expected})')
            picked = uids[:min(PROBE_COUNT, count_expected)]
            subranges.append(((picked[0], picked[-1]), len(picked)))
    finally:
        a.logout()

    print(f'Parallel-Probe: Worker 1 Paket {indices[0]+1}, Worker 2 Paket '
          f'{indices[1]+1}; je max. {PROBE_COUNT} Quellnachrichten.', flush=True)
    print('Bereits uebertragene Nachrichten zaehlen zur spaeteren Vollmigration; '
          'Pakete werden hier noch NICHT als abgeschlossen markiert.', flush=True)
    secure_dir(LOGS)
    fd, path = tempfile.mkstemp(prefix='.pass-', dir=ROOT)
    os.fchmod(fd, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(password + '\n')
        def probe_lane(lane):
            idx = indices[lane]
            uids, expected = subranges[lane]
            with LOCK:
                state.setdefault('in_progress', {})[str(lane)] = [idx]
                save_state(state)
            # Preserve the UID mode and cache path across retries.
            ok, stats, attempts = execute_group(
                [idx], lane, rows, Path(path), uid_range=uids,
                expected_override=expected, log_suffix='-probe',
                combined_rss_limit=PROBE_RSS_LIMIT_MIB)
            with LOCK:
                state.setdefault('attempts', {})[str(idx)] = (
                    state['attempts'].get(str(idx), 0) + attempts)
                if ok:
                    state.setdefault('probe_results', {})[str(idx)] = stats
                    state['in_progress'][str(lane)] = []
                save_state(state)
            if not ok:
                raise RuntimeError(f'Probe Paket {idx+1} fehlgeschlagen: {stats["log"]}')
            return stats
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(probe_lane, i) for i in (0, 1)]
            outcomes = []
            failures = []
            for f in futures:
                try:
                    outcomes.append(f.result())
                except BaseException as exc:
                    failures.append(str(exc))
            if failures:
                raise RuntimeError(' | '.join(failures))
        state['parallel_probed'] = True
        save_state(state)
        copied = sum(x['transferred'] or 0 for x in outcomes)
        skipped = sum(x['skipped'] or 0 for x in outcomes)
        worst = max(x['peak_rss_mib'] or 0 for x in outcomes)
        print(f'PARALLEL-PROBE OK: {copied} Mails kopiert, {skipped} '
              f'bereits vorhanden; groesster einzelner RSS-Wert {worst:.0f} MiB.', flush=True)
        print('Naechster Schritt: Wir pruefen die Logs und die RAM-Reserve. '
              'Erst danach grosse parallele Pakete.', flush=True)
    finally:
        os.unlink(path)


def packet_uid_chunks(uids: list[int], rows: list[tuple[int, int, int]], chunk_size: int):
    """Reproduzierbare, ueberschneidungsfreie Subpakete aus unveraendertem UID-Snapshot."""
    if chunk_size <= 0:
        raise ValueError('ungueltige Chunkgroesse')
    result = []
    for start, end, count_expected in rows:
        lo = bisect.bisect_left(uids, start)
        hi = bisect.bisect_right(uids, end)
        packet = uids[lo:hi]
        if len(packet) != count_expected:
            raise RuntimeError(f'Quell-Paket {start}:{end} geaendert: '
                               f'{len(packet)} statt {count_expected} UIDs')
        result.append([packet[n:n+chunk_size] for n in range(0,len(packet),chunk_size)])
    if sum(sum(len(c) for c in chunks) for chunks in result) != len(uids):
        raise RuntimeError('UID-Plan unvollstaendig oder neue UIDs im alten Bereich')
    return result


def run_two_production(password: str, workers: int = 2, memory_guard: SmartMemoryGuard | None = None):
    """Ein oder zwei produktive Worker mit RAM-Abbruch und Teilpaket-Checkpoints.

    Bewahrt UID-Caches, Paketnummern, UIDVALIDITY und den Manifest-Hash.
    Ein abgeschlossenes Teilpaket wird erst NACH Logpruefung atomar quittiert.
    """
    if workers not in (1, 2):
        raise ValueError('Nur ein oder zwei Worker zulaessig')
    state = load_state()
    rows = batches()
    if not state.get('pilot_checked') or 0 not in state['completed']:
        raise RuntimeError('Pilot und pilot-check muessen erfolgreich abgeschlossen sein')
    if not state.get('parallel_probed'):
        raise RuntimeError('Zuerst den bestandenen V2.2-parallel-probe ausfuehren')
    if state.get('safe_chunk_size', SAFE_CHUNK) != SAFE_CHUNK:
        raise RuntimeError('Chunkgroesse des angefangenen Laufes stimmt nicht mit dem Skript ueberein')
    if state['snapshot_count'] != sum(r[2] for r in rows):
        raise RuntimeError('Quell-Snapshot und Paketplan stimmen nicht ueberein')
    verify_identity(password, state)
    guard_cache_before_resume(state, rows)
    if RUNNING_RSS_MIB:
        raise RuntimeError('RSS-Prozessregister nicht leer: gleichzeitig laufende Worker?')
    # Sicherstellen, dass nach einem unkontrollierten Abbruch kein altes
    # imapsync-Kind unbemerkt weiterkopiert. Nicht fremde Prozesse beenden.
    for lane in (1, 2):
        pidfile = ROOT / f'worker{lane}.pid'
        if pidfile.exists():
            try:
                oldpid = int(pidfile.read_text().splitlines()[0].strip())
                os.kill(oldpid, 0)
            except (OSError, ValueError, IndexError):
                continue
            else:
                raise RuntimeError(f'Worker{lane}: vorhandener Prozess PID {oldpid}. Nicht parallel starten!')
    # Read-only Zielabgleich: bereits quittierte/bei der Probe kopierte Nachrichten
    # duerfen nicht unter den erwarteten Mindestbestand fallen.
    completed_indices = set(state['completed'])
    safe_counts = state.get('safe_chunk_totals', {})
    probed_counts = state.get('probe_results', {})
    baseline = sum(rows[i][2] for i in completed_indices)
    baseline += sum(int(v.get('transferred', 0)) for k, v in probed_counts.items()
                    if int(k) not in completed_indices)
    baseline += sum(int(v.get('transferred', 0)) for k, v in safe_counts.items()
                    if int(k) not in completed_indices)
    dest = target()
    try:
        actual_target = count(dest)
    finally:
        dest.logout()
    print(f'M365-Zielbestand: {actual_target} Nachrichten; durch Status mindestens {baseline} erwartet.',
          flush=True)
    if actual_target < baseline:
        raise RuntimeError('Zielbestand kleiner als bereits quittiert. Keine weitere Migration!')
    if actual_target > baseline:
        print('WARNUNG: Zielbestand groesser als quittiert (z.B. nach unterbrochenem APPEND). '
              'UID-Cache erhalten; spaeter Vollstaendigkeitsaudit zwingend.', flush=True)

    print('Lese Quell-UID-Liste und validiere den unveraenderten Migrations-Snapshot ...', flush=True)
    m = source(password)
    try:
        current_ids = source_uids(m)
    finally:
        m.logout()
    snapshot = [uid for uid in current_ids if uid <= state['snapshot_max_uid']]
    if len(snapshot) != state['snapshot_count'] or digest_uids(snapshot) != state['source_uid_sha256']:
        raise RuntimeError('Quell-UID-Snapshot geaendert. Nicht mit alten Caches fortfahren!')
    chunks_by_packet = packet_uid_chunks(snapshot, rows, SAFE_CHUNK)
    new_uids = len(current_ids) - len(snapshot)
    print(f'Snapshot bestaetigt: {len(snapshot)} alte Nachrichten, '
          f'{new_uids} seit Planung neu hinzugekommen (separat am Ende).', flush=True)
    safety = ('Kernel-Speicherdruck + Swap-Delta + RSS-Grenzen' if memory_guard is not None
              else f'RAM-Grenze {SAFE_RSS_LIMIT_MIB} MiB gemeinsam')
    print(f'Produktivlauf: {workers} Worker, maximal {SAFE_CHUNK} Nachrichten je Teilpaket, '
          f'Schutz: {safety}. '
          f'Vorhandene {sum(rows[i][2] for i in state["completed"])} '
          f'quittierte Nachrichten bleiben unveraendert.', flush=True)

    # Sub-batch boundaries must stay stable across restarts.
    # Parent packets remain separate checkpoint units.
    secure_dir(LOGS)
    fd, passpath = tempfile.mkstemp(prefix='.pass-', dir=ROOT)
    os.fchmod(fd, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(password + '\n')
        pwfile = Path(passpath)
        stopper = threading.Event()
        session = time.strftime('%Y%m%d-%H%M%S') + f'-{os.getpid()}'
        started = time.monotonic()
        state.setdefault('safe_chunk_size', SAFE_CHUNK)
        state.setdefault('safe_chunk_next', {})
        state.setdefault('safe_chunk_totals', {})
        save_state(state)
        def one_lane(lane):
            for idx in range(len(rows)):
                if lane_for(idx,len(rows)) != lane or idx in state['completed']:
                    continue
                if stopper.is_set():
                    return
                pieces = chunks_by_packet[idx]
                with LOCK:
                    completed_chunks = int(state['safe_chunk_next'].get(str(idx), 0))
                    if not 0 <= completed_chunks <= len(pieces):
                        raise RuntimeError(f'Paket {idx+1}: ungueltiger Teilpaket-Checkpoint')
                    state.setdefault('in_progress', {})[str(lane)] = [idx]
                    save_state(state)
                for subindex in range(completed_chunks, len(pieces)):
                    if stopper.is_set():
                        return
                    ids = pieces[subindex]
                    suffix = f'-safe-c{subindex+1:02d}-{session}'
                    ok, stats, attempts = execute_group(
                        [idx], lane, rows, pwfile, uid_range=(ids[0],ids[-1]),
                        expected_override=len(ids), log_suffix=suffix,
                        combined_rss_limit=(SAFE_RSS_LIMIT_MIB if memory_guard is None else None),
                        stop_event=stopper, memory_guard=memory_guard)
                    if not ok:
                        raise RuntimeError(f'Paket {idx+1} Teil {subindex+1}: '
                                           f'Fehler in {stats["log"]}')
                    with LOCK:
                        if state['safe_chunk_next'].get(str(idx),0) != subindex:
                            raise RuntimeError(f'Paket {idx+1}: nichtmonotones Teilpaket-Checkpoint')
                        running = state['safe_chunk_totals'].setdefault(str(idx), {
                            'transferred':0,'skipped':0,'selected':0,'duration_seconds':0.0,
                            'peak_rss_mib':0.0,'chunks':0})
                        running['transferred'] += stats['transferred']
                        running['skipped'] += stats['skipped']
                        running['selected'] += stats['selected']
                        running['chunks'] += 1
                        running['duration_seconds'] += stats['duration_seconds']
                        running['peak_rss_mib'] = max(running['peak_rss_mib'], stats['peak_rss_mib'] or 0)
                        running['last_log'] = stats['log']
                        state['safe_chunk_next'][str(idx)] = subindex+1
                        state['attempts'][str(idx)] = state['attempts'].get(str(idx),0)+attempts
                        save_state(state)
                with LOCK:
                    totals = state['safe_chunk_totals'][str(idx)]
                    if (totals['selected'] != rows[idx][2] or
                        totals['transferred'] + totals['skipped'] != rows[idx][2] or
                        state['safe_chunk_next'][str(idx)] != len(pieces)):
                        raise RuntimeError(f'Paket {idx+1}: Teilpaketsumme falsch: {totals}')
                    if idx not in state['completed']:
                        state['completed'].append(idx)
                        state['completed'].sort()
                    state['results'][str(idx)] = dict(totals,
                        errors=0,missing=0,return_value=0,
                        peak_rss_mib=totals['peak_rss_mib'],
                        log=totals.get('last_log'),expected=rows[idx][2])
                    state['in_progress'][str(lane)] = []
                    save_state(state)
                    total_done = sum(rows[i][2] for i in state['completed'])
                    duration = time.monotonic()-started
                    print(f'[{time.strftime("%H:%M:%S")}] PAKET {idx+1}/{len(rows)} OK '
                          f'| Worker {lane+1} | {total_done}/{state["snapshot_count"]} '
                          f'quittiert | Gesamtlaufzeit {format_elapsed(duration)}', flush=True)
        if workers == 1:
            # Gleiche UID-Caches und Teilpakete wie im Parallelmodus.
            # Nur die zeitliche Ueberlappung wird vermieden.
            one_lane(0)
            one_lane(1)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(one_lane, lane) for lane in (0,1)]
                failures=[]
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        fut.result()
                    except BaseException as exc:
                        stopper.set()
                        failures.append(str(exc))
                if failures:
                    raise RuntimeError('Zwei-Worker-Lauf gestoppt: '+' | '.join(failures))
        if len(state['completed']) != len(rows):
            raise RuntimeError('Nicht alle geplanten Pakete quittiert; bitte status und Logs pruefen')
        print('ALLE SNAPSHOT-PAKETE UEBERTRAGEN. '
              'Jetzt gesondert `audit` ausfuehren. Neue Quellnachrichten separat nachziehen.', flush=True)
    finally:
        os.unlink(passpath)



def run_adaptive(password: str) -> None:
    """Zuerst parallel; nach RAM-Notstopp sicher und dauerhaft seriell.

    Vor dem zweiten Start muessen die beiden imapsync-Kinder von der
    Prozessverwaltung bereits beendet worden sein (ThreadPoolExecutor wartet).
    Verwendet unveraendert die alten Cacheverzeichnisse und Chunkgrenzen.
    """
    state = load_state()
    if state.get('adaptive_single_worker'):
        print('RAM-Schutzmodus ist gespeichert: Fortsetzung mit 1 Worker '
              'und unveraenderten UID-Caches.', flush=True)
        run_two_production(password, workers=1)
        return
    try:
        run_two_production(password, workers=2)
    except RuntimeError as exc:
        if 'RAM-Sicherheitsabbruch:' not in str(exc):
            raise  # Andere Fehler duerfen NICHT als RAM-Ereignis kaschiert werden.
        # Im Zwei-Worker-Pfad wurden beide Kindprozesse bereits beendet/joined.
        # Nur quittierte Teilpakete sind als abgeschlossen gespeichert.
        with LOCK:
            state = load_state()
            state['adaptive_single_worker'] = True
            state['adaptive_switch_reason'] = 'RAM-Limit 5500 MiB bei 2 Workern ueberschritten'
            state['adaptive_switch_time'] = time.strftime('%Y-%m-%d %H:%M:%S %z')
            save_state(state)
        print('\nRAM-SCHUTZ: Beide imapsync-Prozesse beendet; '
              'auf 1 Worker umgestellt (auch bei Neustart).', flush=True)
        print('Begonnene, nicht quittierte Teilpakete werden mit '
              'denselben UID-Caches erneut geprueft.', flush=True)
        run_two_production(password, workers=1)



def recover_after_ram_stop(password: str) -> None:
    """Nach BEREITS beobachtetem RAM-Schutzstopp ohne erneutes Parallelrisiko.

    Expliziter Nutzerbefehl, daher bleibt die Ursache im Zustand vermerkt.
    Die bestehenden UID-Caches und 200er-Checkpointgrenzen bleiben erhalten.
    """
    with LOCK:
        state = load_state()
        state['adaptive_single_worker'] = True
        state['adaptive_switch_reason'] = 'Bekannter RAM-Limit-Abbruch; konservative Wiederaufnahme'
        state['adaptive_switch_time'] = time.strftime('%Y-%m-%d %H:%M:%S %z')
        save_state(state)
    print('RAM-SCHUTZ: Bekannten Abbruch bestaetigt; '
          'Fortsetzung mit genau 1 Worker ohne erneuten Parallelversuch.', flush=True)
    run_two_production(password, workers=1)



def do_memcheck():
    """Liest lokale Speichertelemetrie, ohne Postfaecher oder Migrationsstatus zu aendern."""
    if sys.platform != 'darwin':
        print('ACHTUNG: Diese Speicherdiagnose ist fuer macOS ausgelegt.')
    s = mac_memory_sample()
    print('macOS-Speicher:', describe_memory(s))
    ready, reason = can_start_two(s)
    print('Zwei-Worker-Vorpruefung:', 'JA' if ready else 'NEIN', '|', reason)
    print('Swap-Trend: Erst waehrend einer ueberwachten Migration messbar; '
          'vorhandene Swap-Belegung allein ist kein Fehler.')


def resume_smart(password):
    """Explizite erneute 2-Worker-Freigabe auf Basis der LIVE-Mac-Telemetrie.

    Ein vorhandener serieller Rueckfall ist dauerhaft gespeichert. Die
    Historie bleibt erhalten, aber ein ausdruecklicher neuer Aufruf darf
    nach erfolgreicher Systempruefung nochmals 2 Worker versuchen.
    """
    s = mac_memory_sample()
    ready, reason = can_start_two(s)
    print('SPEICHER-VORPRUEFUNG:', describe_memory(s), flush=True)
    state = load_state()
    if state.get('adaptive_single_worker'):
        print('Bekannter RAM-Abbruch im Status erhalten. '
              'Erneuter Parallelversuch nur durch ausdruecklichen `resume-smart`-Aufruf.', flush=True)
    if not ready:
        print('SYSTEMSCHUTZ: Kein Parallelstart: ' + reason +
              '. Fahre mit 1 Worker und bisheriger RAM-Grenze fort.', flush=True)
        run_two_production(password, workers=1, memory_guard=(SmartMemoryGuard(1) if s.get('pressure') is not None and s.get('swap_used_mib') is not None and s.get('available_pct') is not None else None))
        return
    print('SYSTEMSCHUTZ: 2 Worker freigegeben. Bei Speicherdruck, '
          'starkem Swap-Anstieg oder RSS-Notgrenze folgt sicherer Rueckfall.', flush=True)
    try:
        run_two_production(password, workers=2, memory_guard=SmartMemoryGuard(2))
        return
    except RuntimeError as exc:
        if 'RAM-Sicherheitsabbruch:' not in str(exc):
            raise  # Auth-, Ziel-, Cache- und Snapshotfehler niemals kaschieren.
        state = load_state()
        state['adaptive_single_worker'] = True
        state['adaptive_switch_reason'] = str(exc)[:300]
        state['adaptive_switch_time'] = time.strftime('%Y-%m-%d %H:%M:%S %z')
        state['v25_memory_fallback'] = True
        save_state(state)
        print('\nSYSTEMSCHUTZ: Beide Worker beendet. Kontrollierte Wiederaufnahme '
              'mit 1 Worker; UID-Caches und Checkpoints unveraendert.', flush=True)
        # Systemzustand erst beruhigen lassen. Kein automatischer Restart
        # unter akutem Druck; bei unbekannter Telemetrie fail closed.
        for attempt in range(12):
            sample = mac_memory_sample()
            level = sample.get('pressure')
            avail = sample.get('available_pct')
            if (level in (0,1,None) and avail is not None and
                avail >= SMART_START_AVAILABLE_PCT and
                sample.get('swap_used_mib') is not None):
                print('Speicherreserve wieder ausreichend: ' + describe_memory(sample), flush=True)
                break
            if attempt == 11:
                raise RuntimeError('System weiterhin unter Druck oder Telemetrie unvollstaendig. '
                                   'Kein automatischer Neustart; spaeter `recover` ausfuehren.')
            time.sleep(10)
        # Serielle Fortsetzung mit eigener, weiterhin systemabhaengiger Pruefung.
        run_two_production(password, workers=1, memory_guard=SmartMemoryGuard(1))


def do_pilot_check(password):
    state = load_state()
    rows = batches()
    if 0 not in state['completed']:
        raise RuntimeError('Zuerst `pilot` ausfuehren')
    verify_identity(password, state)
    guard_cache_before_resume(state, rows)
    secure_dir(LOGS)
    passfd, path = tempfile.mkstemp(prefix='.pass-', dir=ROOT)
    try:
        with os.fdopen(passfd, 'w') as f:
            f.write(password + '\n')
        # --dry: KEINE IMAP-Aenderungen, unabhaengiger neuer imapsync-Prozess.
        ok, stats, _ = execute_group([0], 0, rows, Path(path), dry=True)
    finally:
        os.unlink(path)
    if not ok:
        raise RuntimeError('Pilot-Recheck fehlgeschlagen. Keine Parallelmigration!')
    state['pilot_checked'] = True
    save_state(state)
    print('Pilot-Recheck OK: es wuerden 0 E-Mails erneut kopiert.')


def do_audit(password):
    state = load_state()
    rows = batches()
    verify_identity(password, state)
    a = source(password)
    try:
        now_ids = source_uids(a)
    finally:
        a.logout()
    b = target()
    try:
        target_count = count(b)
    finally:
        b.logout()
    prior_ids = [i for i in now_ids if i <= state['snapshot_max_uid']]
    stable = len(prior_ids) == state['snapshot_count'] and digest_uids(prior_ids) == state['source_uid_sha256']
    complete = len(state['completed']) == len(rows)
    exact_count = target_count - state['initial_target_count'] == state['snapshot_count']
    new_count = len(now_ids) - len(prior_ids)
    print(f'Quelle im UID-Snapshot unveraendert: {"JA" if stable else "NEIN"}')
    print(f'Erledigte Pakete: {len(state["completed"])}/{len(rows)}')
    print(f'Snapshot-Quellnachrichten: {state["snapshot_count"]}')
    print(f'Neue Quell-UIDs nach Snapshot: {new_count}')
    print(f'M365-INBOX Nachrichten: {target_count} (Soll fuer Snapshot: {state["snapshot_count"]})')
    if stable and complete and exact_count:
        print('BESTANDSAUDIT OK. Kein kryptografischer Vollinhaltvergleich; Stichproben empfohlen.')
    else:
        raise RuntimeError('Bestandsaudit NICHT bestanden. Keine Loeschung/kein Abschluss!')


def do_status():
    state = load_state()
    rows = batches()
    done = set(state['completed'])
    n_done = sum(rows[i][2] for i in done)
    print(f'Erledigt: {len(done)}/{len(rows)} Pakete; {n_done}/{state["snapshot_count"]} Nachrichten')
    print(f'Pilot kontrolliert: {state["pilot_checked"]} | Parallelitaet getestet: {state["parallel_tested"]}')
    if state.get('adaptive_single_worker'):
        print('RAM-SCHUTZ (gespeichert): serieller Rueckfall nach frueherem RAM-Stopp. '
              '`resume-smart` darf bei gutem Systemzustand 2 Worker testen.')
    else:
        print('RAM-SCHUTZ: 2 Worker moeglich; `resume-smart` prueft Kernel-Druck + Swap-Zunahme')
    if any(state.get('in_progress', {}).values()):
        print('ACHTUNG: Bei Unterbrechung offene, nicht abgeschlossene Pakete:', state['in_progress'])
    if done:
        largest_peak = max((state['results'][str(i)].get('peak_rss_mib') or 0) for i in done)
        print(f'Groesster beobachteter Prozess-RSS-Wert: {largest_peak:.0f} MiB')
    chunks = state.get('safe_chunk_next', {})
    if chunks:
        print('Teilpaketfortschritt in offenen Paketen:',
              ', '.join(f'{int(idx)+1}:{pos}' for idx,pos in sorted(chunks.items(),key=lambda p:int(p[0]))
                        if int(idx) not in done) or 'keine')
    print('Status:', STATE)


def do_selftest():
    cases = [([], []), ([2,3,4], [[2,3], [4]]), ([0,2,3,7], [[0], [2,3], [7]])]
    for pending, exp in cases:
        # test helper using simplified grouping algorithm
        jobs, run = [], []
        for i in pending:
            if run and (i != run[-1]+1 or len(run) >= 2):
                jobs.append(run); run = []
            run.append(i)
        if run: jobs.append(run)
        assert jobs == exp
    assert split_uids([1,3,5]) == [(1,5,3)]
    assert split_uids(list(range(1,4005))) == [(1,2000,2000),(2001,4000,2000),(4001,4004,4)]
    assert lane_for(0,100) == 0 and lane_for(49,100) == 0 and lane_for(50,100) == 1
    sample = '''Host1: folder [INBOX] selected 2000 messages, duplicates 0
Messages transferred                    : 1950
Messages skipped                        : 50
Messages found in host1 not in host2    : 0 messages
Memory consumption at the end           : 6288.5 MiB
Detected 0 errors
Exiting with return value 0 (EX_OK: successful termination) 0/50 nb_errors/max_errors PID 55'''
    met = parse_metrics(sample)
    assert met['selected'] == 2000 and met['ram_end_mib'] == 6288.5
    assert met['transferred'] + met['skipped'] == 2000 and met['return_value'] == 0
    assert met['missing'] == 0 and met['errors'] == 0
    assert parse_swap_used_mib('total = 8192,00M used = 1024,50M free = 7167,50M (encrypted)') == 1024.50
    assert can_start_two({'pressure':1, 'available_pct':52, 'swap_used_mib':1200})[0]
    assert not can_start_two({'pressure':2, 'available_pct':52, 'swap_used_mib':1200})[0]
    assert not can_start_two({'pressure':1, 'available_pct':19, 'swap_used_mib':1200})[0]
    assert not can_start_two({'pressure':None, 'available_pct':60, 'swap_used_mib':1200})[0]
    class FakeClock:
        t = 0
        def __call__(self): return self.t
    class FakeSensor:
        def __init__(self): self.i = 0
        def __call__(self):
            self.i += 1
            return {'pressure': 2 if self.i >= 2 else 1,
                    'available_pct':50, 'swap_used_mib':1200}
    fakeclock = FakeClock()
    memory_guard = SmartMemoryGuard(2, sample_fn=FakeSensor(), clock=fakeclock)
    with LOCK:
        RUNNING_RSS_MIB.clear()
    assert not memory_guard.check(9999, 500)[0]
    fakeclock.t = SMART_SAMPLE_SECONDS
    assert not memory_guard.check(9999, 500)[0]
    fakeclock.t = 2 * SMART_SAMPLE_SECONDS
    assert 'Speicherdruck' in memory_guard.check(9999, 500)[0]
    with LOCK:
        RUNNING_RSS_MIB.clear()
    print('SELFTEST OK: UID-Batches, Worker-Grenzen, Log-Parser, Swap-/Druckpruefung, Warnhysterese.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['selftest','doctor','plan','pilot','pilot-check',
                                           'parallel-probe','parallel-test','run','run-safe','recover','resume-smart','memcheck','status','audit','oauth-refresh'])
    parser.add_argument('--workers', type=int, choices=[1,2], default=1)
    parser.add_argument('--bundle', type=int, choices=[1,2,3], default=1)
    args = parser.parse_args()
    if args.action == 'selftest':
        do_selftest(); return
    if args.action == 'memcheck':
        do_memcheck(); return
    validate_config()
    os.umask(0o077)
    if args.action == 'oauth-refresh':
        refresh_oauth(); return
    if args.action == 'status':
        do_status(); return
    secure_dir(ROOT)
    # Kein zweites gleichzeitiges Exemplar dieses Orchestrators.
    with (ROOT / 'run.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Ein anderer Migrationslauf ist bereits aktiv') from exc
        password = getpass.getpass('Quellpostfach-Passwort: ')
        if args.action == 'doctor': do_doctor(password)
        elif args.action == 'plan': do_plan(password)
        elif args.action == 'pilot': run_selected(password, 'pilot')
        elif args.action == 'pilot-check': do_pilot_check(password)
        elif args.action == 'parallel-probe': do_parallel_probe(password)
        elif args.action == 'parallel-test': run_selected(password, 'parallel-test', 2)
        elif args.action == 'run': run_selected(password, 'run', args.workers, args.bundle)
        elif args.action == 'run-safe': run_adaptive(password)
        elif args.action == 'recover': recover_after_ram_stop(password)
        elif args.action == 'resume-smart': resume_smart(password)
        elif args.action == 'audit': do_audit(password)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nUnterbrochen. Mit derselben Version und unveraendertem Cache fortfahren.', file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print('FEHLER:', e, file=sys.stderr)
        sys.exit(1)
