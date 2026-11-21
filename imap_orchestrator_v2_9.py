"""Restartable four-lane IMAP inbox continuation (public prototype, v2.9).

This module is a separate, opt-in continuation of imap_orchestrator.py.
It retains UID checkpoints and cache ownership when upgrading existing
schema-2 state to schema 3, and measures parallelism (up to four workers).
Keep your existing runtime state and cache directories private and unchanged.
The initial plan, pilot and parallel-probe must have been completed with the
bootstrap orchestrator. New migrations should start with imap_orchestrator.py.

An explicitly configured allowlist of missing source UIDs is optional and
EMPTY by default. Missing UIDs remain audit gaps, never counted as copied.
Source credentials, account names, OAuth helper and access token file are
supplied via environment variables; there are no real accounts in this file.
Use a private work directory outside the checked-out source repository.

Offline checks:
  python3 imap_orchestrator_v2_9.py selftest
  python3 tests/test_v2_9.py
Live continuation only after validating configuration and existing state:
  python3 imap_orchestrator_v2_9.py doctor
  python3 imap_orchestrator_v2_9.py recover --workers 4
  python3 imap_orchestrator_v2_9.py status
  python3 imap_orchestrator_v2_9.py audit

First Ctrl+C lets running sub-batches finish; second Ctrl+C interrupts them.
Never run two orchestrators on the same runtime state concurrently.
No files are deleted from either mailbox. Offline tests are not a substitute
for independent mailbox and attachment integrity verification.
"""
from __future__ import annotations

import argparse
import bisect
from collections import deque
import concurrent.futures
import copy
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
SAFE_CHUNK = 200              # gleiche Groesse wie erfolgreicher Live-Parallel-Probe
HEARTBEAT_SECONDS = 45  # Statusanzeige im Hauptterminal, kein weiterer IMAP-Zugriff
POLL_SECONDS = 2
RETRIES = 3
TIMEOUT_SECONDS = 6 * 3600
SCHEMA = 3
ACTIVE_CACHE_LANES = None
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
        raise RuntimeError('Vorhandener Migrationszustand fehlt; keinen neuen Plan erzeugen.')
    state = json.loads(STATE.read_text(encoding='utf-8'))
    if state.get('schema') not in (2, 3):
        raise RuntimeError('Unbekanntes Status-Schema. Keine automatische Fortsetzung!')
    if ((state.get('source'), state.get('user1'), state.get('target'), state.get('user2'))
            != (SRC, USER1, DST, USER2)):
        raise RuntimeError('Zustand gehoert zu anderen Konten/Servern')
    if state['manifest_sha256'] != hashlib.sha256(MANIFEST.read_bytes()).hexdigest():
        raise RuntimeError('UID-Manifest nachtraeglich geaendert!')
    if state['schema'] == 3:
        if not state.get('cache_lane_plan'):
            raise RuntimeError('V2.9-Status ohne verbindliche Cache-Zuordnung; nicht kopieren.')
        _validate_stored_plan(state, batches(), state['cache_lane_plan'])
    elif state.get('cache_lane_plan'):
        raise RuntimeError('Cache-Zuordnung und altes Status-Schema widersprechen sich.')
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
            raise RuntimeError(f'OAuth-Refresh fehlgeschlagen (Exit {p.returncode}); vertrauliche Helfer-Ausgabe unterdrueckt')


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
    print(f'Quell-INBOX: {src_count} | Ziel-INBOX: {dst_count}')
    print(f'UIDVALIDITY Quelle: {src_validity} | Ziel: {dst_validity}')
    if STATE.exists():
        s = load_state()
        if (src_validity, dst_validity) != (s['uidvalidity1'], s['uidvalidity2']):
            raise RuntimeError('UIDVALIDITY passt nicht zum Status')
        print('Migration bereits vorbereitet. Vorhandenen Zustand beibehalten!')
    elif dst_count:
        raise RuntimeError('Ziel nicht leer, ohne v2-Status. Nicht mit leerem Cache starten!')
    else:
        print('STARTVORAUSSETZUNGEN ERFUELLT (ohne Aenderung an den Postfaechern).')


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
    owners = ACTIVE_CACHE_LANES
    if not indices or any((owners.get(str(i)) if owners is not None
                               else lane_for(i, len(rows))) != lane for i in indices):
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








def follow_current_run(workers: int = 4) -> None:
    """Genau ein Nachfolger wartet auf run.lock, ohne den aktiven Lauf zu stoppen.

    Das Passwort wird einmal beim Bereitstellen abgefragt. Es wird nicht in
    einem neuen Passwortfile abgelegt, solange der vorhandene Lauf aktiv ist.
    Die bestehende Wiederaufnahmepruefung entscheidet erst NACH der Uebernahme
    ueber Snapshot, Cache und eventuell noch lebende imapsync-Kinder.
    """
    with (ROOT / 'follow.lock').open('a+') as follow_lock:
        try:
            fcntl.flock(follow_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Ein automatischer Nachfolger wartet bereits; kein zweites Exemplar starten') from exc
        password = getpass.getpass('Quellpostfach-Passwort (fuer automatische Fortsetzung): ')
        with (ROOT / 'run.lock').open('a+') as run_lock:
            announced = False
            last_message = time.monotonic()
            while True:
                try:
                    fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    now = time.monotonic()
                    if not announced or now - last_message >= HEARTBEAT_SECONDS:
                        print(f'[{time.strftime("%H:%M:%S")}] UEBERNAHME BEREIT: '
                              'Der bisherige Lauf ist aktiv. V2.9 startet danach automatisch; '
                              'es laeuft kein zweiter Transfer.', flush=True)
                        last_message = now
                        announced = True
                    time.sleep(POLL_SECONDS)
            state = load_state()
            rows = batches()
            if set(state['completed']) == set(range(len(rows))):
                print('Der vorhandene Lauf hat alle Snapshot-Pakete quittiert. '
                      'Kein neuer Transfer; abschliessend audit ausfuehren.', flush=True)
                return
            print('UEBERNAHME: bisheriger Lauf beendet; pruefe Status und setze automatisch mit V2.9 fort.', flush=True)
            recover_parallel(password, workers=workers)


def imapsync_environment(base=None) -> dict:
    """Nur die effektive Meldungs-Locale aendern; andere Kategorien erhalten.

    Upstream: https://github.com/imapsync/imapsync/issues/312
    LC_ALL hat Vorrang vor LC_MESSAGES. Seine bisherige Wirkung auf die
    anderen POSIX-Kategorien bleibt durch explizite Einzelwerte bestehen.
    """
    child_env = dict(os.environ if base is None else base)
    all_locale = child_env.pop('LC_ALL', None)
    if all_locale:
        for category in ('LC_CTYPE', 'LC_COLLATE', 'LC_MONETARY', 'LC_NUMERIC', 'LC_TIME'):
            child_env[category] = all_locale
    child_env['LC_MESSAGES'] = 'C'
    return child_env


class ContinuousMemoryMonitor:
    """Speicherwerte beobachten und gegebenenfalls kuenftige Parallelitaet senken.

Kein Signal, keine RAM-Pause und kein Abbruch laufender Transfers. Bei zwei
Workern wird eine Reduktion auf einen Worker an der naechsten Teilpaketgrenze
angefordert. Die Anforderung bleibt fuer diesen Lauf gesetzt.
"""

    warn_only = True
    SAMPLE_SECONDS = 10
    WARNING_SECONDS = 45
    RSS_WARNING_MIB = 7680
    COMBINED_WARNING_MIB = 10240
    SWAP_WINDOW_SECONDS = 90
    SWAP_WARNING_MIB = 512

    def __init__(self, workers=1, *, sample_fn=None, clock=None, output_fn=None):
        if isinstance(workers, bool) or workers not in (1, 2, 3, 4):
            raise ValueError('ContinuousMemoryMonitor erlaubt einen bis vier Worker')
        self.workers = workers
        self.sample_fn = sample_fn or mac_memory_sample
        self.clock = clock or time.monotonic
        self.output_fn = output_fn or (lambda message: print(message, flush=True))
        self.lock = threading.RLock()
        self.last_sample = None
        self.last_sample_time = None
        self.last_delta_mib = 0.0
        self._last_warning_time = None
        self.swap_history = deque()
        self.serial_requested = threading.Event()
        self.serial_reason = ''

    @staticmethod
    def _number(value, minimum=0, maximum=None):
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and value == value and abs(value) != float('inf')
                and value >= minimum and (maximum is None or value <= maximum))

    def _sample(self, now):
        try:
            raw = self.sample_fn()
            if not isinstance(raw, dict):
                raw = {}
        except Exception:
            raw = {}
        pressure = raw.get('pressure')
        if isinstance(pressure, bool) or pressure not in (0, 1, 2, 4):
            pressure = None
        reserve = raw.get('available_pct')
        if not self._number(reserve, maximum=100):
            reserve = None
        swap = raw.get('swap_used_mib')
        if not self._number(swap):
            swap = None
        self.last_sample = dict(raw, pressure=pressure, available_pct=reserve,
                                swap_used_mib=swap, monotonic=now)
        self.last_sample_time = now
        while self.swap_history and now - self.swap_history[0][0] > self.SWAP_WINDOW_SECONDS:
            self.swap_history.popleft()
        if swap is not None:
            self.swap_history.append((now, float(swap)))
            self.last_delta_mib = max(0.0, float(swap) - self.swap_history[0][1])
        else:
            self.last_delta_mib = 0.0
        return self.last_sample

    def _warn(self, now, details):
        if not details:
            return
        if (self._last_warning_time is not None
                and now - self._last_warning_time < self.WARNING_SECONDS):
            return
        self._last_warning_time = now
        try:
            self.output_fn('SPEICHER-HINWEIS: ' + '; '.join(details) +
                           '. Laufende Transfers werden deshalb weder pausiert noch beendet.')
        except Exception:
            pass

    def _request_serial(self, reasons):
        if self.workers == 1 or not reasons or self.serial_requested.is_set():
            return
        self.serial_reason = '; '.join(reasons)
        self.serial_requested.set()
        controller = getattr(self, 'parallel_controller', None)
        if controller is not None:
            controller.degrade(self.serial_reason, limit=1)
        try:
            self.output_fn('RAM-HINWEIS: ' + self.serial_reason +
                           '. Laufende Teilpakete abschliessen; danach ein Worker, '
                           'die Migration laeuft weiter. Kein laufender Transfer wird abgebrochen.')
        except Exception:
            pass

    def check(self, pid, rss):
        """Immer ('', Systemmesswerte, kombinierter RSS); niemals Stoppsignal."""
        with self.lock:
            if not self._number(rss):
                rss = None
            with LOCK:
                RUNNING_RSS_MIB[pid] = float(rss) if rss is not None else 0.0
                combined = sum(value for value in RUNNING_RSS_MIB.values()
                               if self._number(value))
            now = self.clock()
            if (self.last_sample_time is None
                    or now - self.last_sample_time >= self.SAMPLE_SECONDS):
                self._sample(now)
            sample = self.last_sample
            details = []
            serial_reasons = []
            if rss is None:
                details.append('Prozess-RAM nicht messbar')
            elif rss >= self.RSS_WARNING_MIB:
                reason = f'Prozess-RAM {rss:.0f} MiB >= {self.RSS_WARNING_MIB} MiB'
                details.append(reason)
                serial_reasons.append(reason)
            if combined >= self.COMBINED_WARNING_MIB:
                reason = f'Gemeinsamer Prozess-RAM {combined:.0f} MiB >= {self.COMBINED_WARNING_MIB} MiB'
                details.append(reason)
                serial_reasons.append(reason)
            pressure = sample['pressure']
            if pressure == 4:
                details.append('macOS-Speicherdruck KRITISCH')
                serial_reasons.append('macOS-Speicherdruck KRITISCH')
            elif pressure == 2:
                details.append('macOS-Speicherdruck erhoeht')
            elif pressure is None:
                details.append('macOS-Speicherdruck unbekannt')
            reserve = sample['available_pct']
            if reserve is None:
                details.append('Kernel-Reserve unbekannt')
            elif reserve < 20:
                details.append(f'Kernel-Reserve {reserve:g}%')
            if sample['swap_used_mib'] is None:
                details.append('Swap-Messwert unbekannt')
            elif self.last_delta_mib >= self.SWAP_WARNING_MIB:
                details.append(f'Swap-Zunahme +{self.last_delta_mib:.0f} MiB innerhalb von 90 Sekunden')
            controller = getattr(self, 'parallel_controller', None)
            if controller is not None and not serial_reasons and (
                    pressure == 2 or self.last_delta_mib >= self.SWAP_WARNING_MIB
                    or (reserve is not None and reserve < 15)):
                controller.degrade('Speicherreserve sinkt; Parallelitaet vorsichtig senken', limit=2)
            self._request_serial(serial_reasons)
            self._warn(now, details)
            return '', sample, combined


# AdaptiveParallelism and its four-lane gate are embedded below.




class AdaptiveParallelism:
    """Measure productive stages, draining all old chunks before changing stage.

``limit`` is the selected admission cap, not a count of active transfers.
Memory or throttling reductions affect new admissions only. ``degrade`` is
sticky for this controller's lifetime. A stage stops admitting new chunks once
it has enough observations at ``stage_seconds``, or at twice that duration
with an inconclusive result. Already active work always finishes normally.
"""

    def __init__(self, max_workers=4, *, initial_limit=None, benchmark=True,
                 clock=None, stage_seconds=300, min_successful_chunks=4,
                 min_transferred=400, minimum_gain=.10,
                 max_size_ratio=1.5, output_fn=None):
        if isinstance(max_workers, bool) or max_workers not in (1, 2, 3, 4):
            raise ValueError('max_workers must be between one and four')
        if initial_limit is None:
            initial_limit = min(2, max_workers) if benchmark else max_workers
        if (isinstance(initial_limit, bool) or not isinstance(initial_limit, int)
                or not 1 <= initial_limit <= max_workers):
            raise ValueError('initial_limit must be within max_workers')
        if stage_seconds <= 0 or min_successful_chunks < 1 or min_transferred < 1:
            raise ValueError('measurement window and minimum sample must be positive')
        if minimum_gain < 0 or max_size_ratio < 1:
            raise ValueError('invalid comparison thresholds')
        self.max_workers = max_workers
        self.initial_limit = initial_limit
        self.clock = clock or time.monotonic
        self.output_fn = output_fn or (lambda text: print(text, flush=True))
        self.stage_seconds = float(stage_seconds)
        self.min_successful_chunks = int(min_successful_chunks)
        self.min_transferred = int(min_transferred)
        self.minimum_gain = float(minimum_gain)
        self.max_size_ratio = float(max_size_ratio)
        self.lock = threading.RLock()
        self.active = set()
        self._limit = initial_limit
        self._benchmark = bool(benchmark and initial_limit < max_workers)
        self.phase = 'baseline' if self._benchmark else 'fixed'
        self.draining = False
        self.safety_limited = False
        self.safety_limit = None
        self.safety_reason = ''
        self.reference = None
        self.history = []
        self._new_stage_locked()

    @property
    def limit(self):
        with self.lock:
            return self._limit

    @property
    def selected_workers(self):
        return self.limit

    def _new_stage_locked(self):
        self.stage = dict(started=None, completed_chunks=0, useful_chunks=0,
                          transferred=0, copied_bytes=0, covered_messages=0,
                          failed_chunks=0, peak_active=0, workers=self._limit,
                          mixed_parallelism=False)

    def _emit_locked(self, text):
        try:
            self.output_fn(text)
        except Exception:
            # Diagnostic output must not abort a productive transfer.
            pass

    def _summary_locked(self, now):
        s = self.stage
        elapsed = max(0., now - s['started']) if s['started'] is not None else 0.
        transferred = s['transferred']
        byte_complete = transferred > 0 and s['covered_messages'] == transferred
        return dict(workers=s['workers'], selected_workers=self._limit,
                    mixed_parallelism=s['mixed_parallelism'], elapsed_seconds=elapsed,
                    completed_chunks=s['completed_chunks'], useful_chunks=s['useful_chunks'],
                    transferred=transferred, failed_chunks=s['failed_chunks'],
                    copied_bytes=s['copied_bytes'] if byte_complete else None,
                    messages_per_second=transferred / elapsed if elapsed > 0 else None,
                    bytes_per_second=s['copied_bytes'] / elapsed if elapsed > 0 and byte_complete else None,
                    mean_message_bytes=s['copied_bytes'] / transferred if byte_complete else None,
                    peak_active=s['peak_active'])

    def _enough_locked(self):
        return (self.stage['useful_chunks'] >= self.min_successful_chunks and
                self.stage['transferred'] >= self.min_transferred and
                self.stage['peak_active'] >= self._limit)

    def _proven_limit_locked(self):
        return self.reference['workers'] if self.reference else self.initial_limit

    def _freeze_locked(self, limit, reason, *, safety=False, phase='frozen'):
        old_limit = self._limit
        self._limit = min(self._limit, limit)
        if self._limit != old_limit and self.stage['started'] is not None:
            self.stage['mixed_parallelism'] = True
        self._benchmark = False
        self.draining = False
        self.phase = phase
        if safety:
            self.safety_limited = True
            self.safety_limit = self._limit
            self.safety_reason = reason
        self._emit_locked(f'PARALLELITAET: maximal {self._limit} Worker. {reason} '
                          'Laufende Teilpakete werden abgeschlossen.')

    def _finish_stage_locked(self, now):
        if self.active:
            raise RuntimeError('stage transition requires all old chunks to finish')
        result = self._summary_locked(now)
        result['phase'] = self.phase
        enough = self._enough_locked()
        result['sample_sufficient'] = enough
        self.history.append(result)
        rate = result['messages_per_second']
        byte_rate = result['bytes_per_second']
        self._emit_locked(
            f'MESSUNG: {result["workers"]} Worker | {result["transferred"]} neue Kopien | '
            f'{result["elapsed_seconds"]:.1f}s | '
            f'{rate:.2f} Mails/s | ' +
            (f'{byte_rate / 1024:.1f} KiB/s' if byte_rate is not None else 'Byte-Rate unbekannt'))
        if not enough:
            result['decision'] = 'inconclusive_sample'
            self._freeze_locked(self._proven_limit_locked(),
                                'Messprobe zu klein oder Parallelitaet nicht ausgelastet; keine weitere Erhoehung.')
            return
        if self.reference is None:
            if result['mean_message_bytes'] is None or result['mean_message_bytes'] <= 0:
                result['decision'] = 'inconclusive_bytes'
                self._freeze_locked(self.initial_limit,
                                    'Byte-Messwerte der Ausgangsstufe fehlen; keine weitere Erhoehung.')
                return
            self.reference = dict(result)
            result['decision'] = 'baseline_recorded'
        else:
            reference = self.reference
            old_size, new_size = reference['mean_message_bytes'], result['mean_message_bytes']
            comparable = (old_size is not None and new_size is not None and old_size > 0
                          and 1 / self.max_size_ratio <= new_size / old_size <= self.max_size_ratio)
            result['comparable_message_sizes'] = comparable
            if not comparable:
                result['decision'] = 'inconclusive_sizes'
                self._freeze_locked(reference['workers'],
                                    'Mailgroessen zu verschieden oder Byte-Messwerte fehlen; Vergleich nicht belastbar.')
                return
            old_rate = reference['messages_per_second']
            gain = rate / old_rate - 1 if old_rate and rate is not None else None
            result['relative_gain'] = gain
            if gain is None or gain + 1e-12 < self.minimum_gain:
                result['decision'] = 'insufficient_gain'
                self._freeze_locked(reference['workers'],
                                    'Weniger als die geforderte Durchsatzverbesserung; niedrigere Parallelitaet beibehalten.')
                return
            result['decision'] = 'gain_accepted'
            self.reference = dict(result)
            self._emit_locked(f'MESSVERGLEICH: etwa {gain * 100:.1f}% mehr Mails/s. '
                              'Dies ist eine Schaetzung aus unterschiedlichen produktiven Nachrichten.')
        if self._limit >= self.max_workers:
            result['decision'] = 'maximum_accepted'
            self._benchmark = False
            self.draining = False
            self.phase = 'selected'
            self._emit_locked(f'PARALLELITAET GEWAEHLT: maximal {self._limit} Worker.')
            return
        self._limit += 1
        self.phase = 'candidate'
        self.draining = False
        self._new_stage_locked()
        self._emit_locked(f'NAECHSTE PRODUKTIVE MESSSTUFE: maximal {self._limit} Worker. '
                          'Messzeit beginnt mit dem ersten neuen Teilpaket.')

    def _tick_locked(self, now):
        if not self._benchmark or self.stage['started'] is None:
            return
        elapsed = max(0., now - self.stage['started'])
        if not self.draining and ((elapsed >= self.stage_seconds and self._enough_locked())
                                  or elapsed >= 2 * self.stage_seconds):
            self.draining = True
            self._emit_locked('MESSSTUFE ABSCHLIESSEN: laufende Teilpakete fertigstellen; '
                              'danach automatische Auswertung, keine erneute Kopie fuer den Test.')
        if self.draining and not self.active:
            self._finish_stage_locked(now)

    def tick(self):
        with self.lock:
            self._tick_locked(self.clock())

    def on_chunk_started(self, lane):
        """Atomically admit and record a start; return False while capacity is full."""
        if isinstance(lane, bool) or lane not in (0, 1, 2, 3):
            raise ValueError('cache lane must be zero through three')
        with self.lock:
            if lane in self.active:
                raise RuntimeError('cache lane already active')
            now = self.clock()
            self._tick_locked(now)
            if self.draining or len(self.active) >= self._limit:
                return False
            if self.stage['started'] is None:
                self.stage['started'] = now
            self.active.add(lane)
            self.stage['peak_active'] = max(self.stage['peak_active'], len(self.active))
            return True

    def on_chunk_finished(self, lane, *, transferred=0, copied_bytes=None, successful=False):
        """Remove a running chunk and account only a validated successful result."""
        with self.lock:
            if lane not in self.active:
                raise RuntimeError('chunk finished without active cache lane')
            self.active.remove(lane)
            if isinstance(transferred, bool) or not isinstance(transferred, int) or transferred < 0:
                successful = False
            if (isinstance(copied_bytes, bool) or not isinstance(copied_bytes, int)
                    or copied_bytes < 0):
                copied_bytes = None
            if successful:
                self.stage['completed_chunks'] += 1
                if transferred > 0:
                    self.stage['useful_chunks'] += 1
                    self.stage['transferred'] += transferred
                    if copied_bytes is not None:
                        self.stage['copied_bytes'] += copied_bytes
                        self.stage['covered_messages'] += transferred
            else:
                self.stage['failed_chunks'] += 1
                self._freeze_locked(min(2, self._proven_limit_locked()),
                                    'Ein Teilpaket war nicht erfolgreich; weitere Steigerung ausgesetzt.',
                                    safety=True, phase='error-limited')
            self._tick_locked(self.clock())

    def degrade(self, reason, limit=1):
        """Sticky admission reduction; existing transfers remain active."""
        if isinstance(limit, bool) or limit not in (1, 2):
            raise ValueError('safety limit must be one or two workers')
        with self.lock:
            changed = self._benchmark or not self.safety_limited or limit < self._limit
            if changed:
                self._freeze_locked(limit, str(reason), safety=True, phase='safety-limited')

    def limit_for_memory(self, reason='Speicherdruck', limit=1):
        self.degrade(reason, limit=limit)

    def snapshot(self):
        with self.lock:
            now = self.clock()
            return dict(selected_workers=self._limit, max_workers=self.max_workers,
                        phase=self.phase, draining=self.draining,
                        safety_limited=self.safety_limited, safety_limit=self.safety_limit,
                        safety_reason=self.safety_reason,
                        active_lanes=sorted(self.active),
                        benchmark_active=self._benchmark,
                        reference=dict(self.reference) if self.reference else None,
                        current=self._summary_locked(now),
                        history=[dict(entry) for entry in self.history])


class ChunkConcurrencyGate:
    """FIFO admission across four fixed cache lanes, even with a cap of one.

Call acquire before starting a chunk, then release exactly once in finally.
Pass successful statistics to release only after the checkpoint is persisted.
The controller never takes this gate's lock or calls back into the gate, so the
lock order is always condition -> controller. Waits also poll stop/drain flags.
"""
    WAIT_SECONDS = .2

    def __init__(self, controller):
        self.controller = controller
        self.monitor = controller  # compatibility name for diagnostic callers
        self.condition = threading.Condition()
        self.waiting = deque()
        self.active = set()

    def acquire(self, lane, stop_event=None, drain_event=None):
        if isinstance(lane, bool) or lane not in (0, 1, 2, 3):
            raise ValueError('cache lane must be zero through three')
        with self.condition:
            if lane in self.active or lane in self.waiting:
                raise RuntimeError('cache lane already admitted or waiting')
            self.waiting.append(lane)
            try:
                while True:
                    if ((stop_event is not None and stop_event.is_set()) or
                            (drain_event is not None and drain_event.is_set())):
                        return False
                    self.controller.tick()
                    if self.waiting[0] == lane and self.controller.on_chunk_started(lane):
                        self.waiting.popleft()
                        self.active.add(lane)
                        self.condition.notify_all()
                        return True
                    self.condition.wait(timeout=self.WAIT_SECONDS)
            finally:
                if lane in self.waiting:
                    self.waiting.remove(lane)
                    self.condition.notify_all()

    def release(self, lane, *, transferred=0, copied_bytes=None, successful=False):
        with self.condition:
            if lane not in self.active:
                raise RuntimeError('release without active cache lane')
            self.controller.on_chunk_finished(lane, transferred=transferred,
                                              copied_bytes=copied_bytes, successful=successful)
            self.active.remove(lane)
            self.condition.notify_all()

    def wake_all(self):
        with self.condition:
            self.condition.notify_all()


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


# Aktuelle RSS-Messwerte der produktiven Worker dieses Laufs.
RUNNING_RSS_MIB: dict[int, float] = {}

def execute(command: list[str], logfile: Path, timeout=TIMEOUT_SECONDS,
            *, label: str = '', expected: int | None = None,
            combined_rss_limit: int | None = None,
            stop_event: threading.Event | None = None,
            memory_guard: ContinuousMemoryMonitor | None = None) -> tuple[int, float | None, float]:
    """Transfer beobachten. Speicherwerte duerfen ihn nicht beenden.

    combined_rss_limit bleibt nur als ungenutzter Kompatibilitaetsparameter.
    Integritaetsfehler, Prozessfehler, Bedienabbruch und der vorhandene
    technische Timeout sind davon unabhaengig.
    """
    monitor = memory_guard or ContinuousMemoryMonitor(workers=1)
    start = time.monotonic()
    peak = None
    progress = LogProgress(logfile)
    last_heartbeat = start
    with logfile.open('wb') as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True, env=imapsync_environment())
        if label:
            print(f'[{time.strftime("%H:%M:%S")}] START {label} | '
                  f'imapsync PID {proc.pid} | Fortschritt alle {HEARTBEAT_SECONDS}s', flush=True)
        try:
            while proc.poll() is None:
                if stop_event is not None and stop_event.is_set():
                    raise RuntimeError('Transfer durch die Prozesssteuerung gestoppt')
                usage = rss_mib(proc.pid)
                if usage is not None:
                    peak = max(peak or 0, usage)
                _, _, combined = monitor.check(proc.pid, usage)
                now = time.monotonic()
                if now - start > timeout:
                    raise RuntimeError(f'Technischer Transfer-Timeout nach {timeout} Sekunden; siehe lokales Log')
                if label and now - last_heartbeat >= HEARTBEAT_SECONDS:
                    delta, length = progress.sample()
                    stillness = now - progress.last_change
                    count_text = (f'{progress.copied}/{expected} Kopien im Log' if expected is not None
                                  else f'{progress.copied} Kopien im Log')
                    ram_text = f'{usage:.0f} MiB' if usage is not None else 'unbekannt'
                    note = (' | ACHTUNG: seit >3 min keine neue Logausgabe; '
                            'Prozess lebt, Datenfortschritt unklar' if stillness > 180 else '')
                    system_text = (f' | System {describe_memory(monitor.last_sample)}'
                                   if monitor.last_sample is not None else '')
                    print(f'[{time.strftime("%H:%M:%S")}] AKTIV {label} | '
                          f'PID {proc.pid} | Laufzeit {format_elapsed(now-start)} | '
                          f'{count_text} | Log {length/1024:.0f} KiB '
                          f'(+{delta/1024:.0f} KiB seit letzter Meldung) | '
                          f'RAM {ram_text} | Worker-RAM gesamt {combined:.0f} MiB{system_text}{note}', flush=True)
                    last_heartbeat = now
                time.sleep(POLL_SECONDS)
            rc = proc.wait()
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=20)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            raise
        finally:
            with LOCK:
                RUNNING_RSS_MIB.pop(proc.pid, None)
    if label:
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
    attempt_count = 0
    # Only a specifically recognized server throttle extends the retry budget.
    # Unknown/integrity/authentication failures do not receive unlimited retries.
    for trial in range(1, 7):
        if stop_event is not None and stop_event.is_set():
            raise RuntimeError('Migration gestoppt; kein weiterer Retry')
        attempt_count = trial
        log = LOGS / f'p{start_id:04d}-{end_id:04d}-w{lane+1}{log_suffix}-try{trial}{"-dry" if dry else ""}.log'
        cmd = command_for(ids, rows, lane, pwfile, dry=dry, uid_range=uid_range)
        kind = 'PRUEFUNG' if dry else 'TRANSFER'
        effective = uid_range or (rows[ids[0]][0], rows[ids[-1]][1])
        label = (f'{kind} Cache-Worker {lane+1}, Paket {start_id}-{end_id}{log_suffix}, '
                 f'Versuch {trial}, UID {effective[0]}:{effective[1]}')
        rc, peak, seconds = execute(cmd, log, label=label, expected=expected,
                                    combined_rss_limit=combined_rss_limit,
                                    stop_event=stop_event, memory_guard=memory_guard)
        log_text = log.read_text(errors='replace')
        stats = parse_metrics(log_text)
        measured_copies, copied_bytes = copied_log_metrics(log_text)
        throttled, requested_delay = throttle_details(log_text)
        stats.update(returncode=rc, peak_rss_mib=round(peak, 1) if peak else None,
                     duration_seconds=round(seconds, 1), log=str(log), expected=expected,
                     measured_copies=measured_copies, copied_bytes=copied_bytes,
                     throttle_detected=throttled)
        valid = (rc == 0 and stats['return_value'] == 0 and stats['errors'] == 0
                 and stats['selected'] == expected and stats['missing'] == 0)
        if dry:
            valid = (valid and stats['would_transfer'] in (None, 0)
                     and stats['transferred'] == 0 and stats['skipped'] == expected)
        else:
            valid = valid and stats['transferred'] is not None and stats['skipped'] is not None
            valid = valid and stats['transferred'] + stats['skipped'] == expected
        last = stats
        controller = getattr(memory_guard, 'parallel_controller', None)
        if throttled and controller is not None:
            with memory_guard.lock:
                memory_guard.throttle_events = getattr(memory_guard, 'throttle_events', 0) + 1
                throttle_events = memory_guard.throttle_events
            controller.degrade('Serverdrosselung im Transferlog', limit=2 if throttle_events == 1 else 1)
        elif not valid and controller is not None:
            controller.degrade('Transferfehler; vorsichtige automatische Wiederholung', limit=2)
        print(f'Paket {start_id}–{end_id}, Cache-Worker {lane+1}, Versuch {trial}: '
              f'{"OK" if valid else "FEHLER"} | transferiert={stats["transferred"]}, '
              f'uebersprungen={stats["skipped"]}, RSS-peak={stats["peak_rss_mib"]} MiB | {log}', flush=True)
        if valid:
            return True, stats, trial
        retry_budget = 6 if throttled else RETRIES
        if trial >= retry_budget:
            break
        retry_wait(max(45.0, requested_delay), stop_event, f'Cache-Worker {lane+1}')
    return False, last, attempt_count


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


def guard_cache_before_resume(state: dict, rows, *, target_messages=None):
    """Check every touched cache lane, independently of requested concurrency.

    An unadmitted waiting lane is not touched. A saved in-progress marker may
    represent an unacknowledged APPEND and therefore cannot waive this check.
    """
    touched = set(state.get('completed', [])) | set(state.get('available_processed', []))
    for field in ('attempts', 'results', 'safe_chunk_next', 'safe_chunk_totals', 'probe_results'):
        touched.update(int(key) for key in state.get(field, {}))
    touched.update(index for group in state.get('in_progress', {}).values() for index in group)
    for lane in range(4):
        had_work = any(packet_cache_lane(state, index, len(rows)) == lane for index in touched)
        cache = ROOT / f'cache-worker{lane+1}' / 'imapsync_cache'
        if had_work and (not cache.is_dir() or not any(path.is_file() for path in cache.rglob('*'))):
            raise RuntimeError(f'Cache-Worker {lane+1}: bisheriger UID-Cache fehlt. Nicht erneut kopieren!')
    if not touched and target_messages:
        if not any((ROOT / f'cache-worker{lane+1}' / 'imapsync_cache').is_dir()
                   and any(p.is_file() for p in
                           (ROOT / f'cache-worker{lane+1}' / 'imapsync_cache').rglob('*'))
                   for lane in range(4)):
            raise RuntimeError('Ziel nicht leer, aber kein UID-Cache/Status vorhanden!')


def observed_ram_mib(state: dict) -> float | None:
    # Der hoehere Wert aus RSS-Abtastung und imapsync-Endspeicherwert.
    values = []
    for result in state.get('results', {}).values():
        for key in ('peak_rss_mib', 'ram_end_mib'):
            if isinstance(result.get(key), (int, float)):
                values.append(float(result[key]))
    return max(values) if values else None








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


class WorkerRunControl:
    """First interrupt drains current chunks; a second requests cancellation.

    Signal handlers live in the main thread. Workers always finish/join before
    the password file or run lock can be released.
    """

    def __init__(self):
        self.stop_event = threading.Event()
        self.drain_event = threading.Event()
        self.gate = None
        self.previous = {}

    def request_stop(self, signum=None, frame=None):
        if self.drain_event.is_set():
            self.stop_event.set()
            print('SOFORTSTOPP angefordert. Letztes APPEND kann unklar bleiben; '
                  'UID-Caches fuer Wiederaufnahme erhalten.', flush=True)
        else:
            self.drain_event.set()
            print('STOPP ANGEFORDERT: laufende Teilpakete werden fertiggestellt '
                  'und gespeichert; danach keine neuen Teilpakete.', flush=True)
        if self.gate is not None:
            self.gate.wake_all()

    def __enter__(self):
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGINT, signal.SIGTERM):
                self.previous[signum] = signal.signal(signum, self.request_stop)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)
        return False


def configured_source_gaps() -> tuple[int, ...]:
    """Explicit source-UID exceptions. Never silently allow known losses."""
    raw = os.getenv('IMAP_ALLOWED_MISSING_UIDS', '').strip()
    if not raw:
        return ()
    values = [value for value in re.split(r'[,\s]+', raw) if value]
    try:
        parsed = tuple(int(value) for value in values)
    except ValueError as exc:
        raise RuntimeError('IMAP_ALLOWED_MISSING_UIDS muss eine Liste von UID-Zahlen sein') from exc
    if any(uid < 1 or uid > 4294967295 for uid in parsed) or len(set(parsed)) != len(parsed):
        raise RuntimeError('IMAP_ALLOWED_MISSING_UIDS enthaelt ungueltige/mehrfache UIDs')
    return parsed


ALLOWED_SOURCE_GAPS = configured_source_gaps()


LEGACY_CHUNK_SIZE = 200


def _digest_uids(uids):
    digest = hashlib.sha256()
    for uid in uids:
        digest.update(f'{uid}\n'.encode('ascii'))
    return digest.hexdigest()


def _nonnegative_integer(value, label):
    if type(value) is not int or value < 0:
        raise RuntimeError(f'{label}: keine nichtnegative ganze Zahl.')
    return value


def _validate_rows(rows):
    if not rows:
        raise RuntimeError('Leerer urspruenglicher Paketplan.')
    previous_end = 0
    total = 0
    for start, end, expected in rows:
        if (any(type(value) is not int for value in (start, end, expected))
                or start <= previous_end or end < start or end > 4294967295
                or expected < 1 or expected > 2000 or end - start + 1 < expected):
            raise RuntimeError('Ungueltiger urspruenglicher Paketplan.')
        previous_end = end
        total += expected
    return total


def verify_original_snapshot(state, rows, current_ids,
                             allowed_missing=ALLOWED_SOURCE_GAPS):
    """Return (original_uids, missing_tuple, new_count) only with original SHA.

    UIDs beyond the original maximum are new arrivals and remain excluded.
    Otherwise only absent, explicitly allowed UIDs may be inserted. The entire
    reconstructed list must reproduce both the original SHA-256 and count.
    Unknown losses, substitutions, additions and changes to the plan fail.
    UIDVALIDITY must be verified by the caller before invoking this helper.
    """
    planned_count = _validate_rows(rows)
    expected_count = state['snapshot_count']
    cutoff = state['snapshot_max_uid']
    if (type(expected_count) is not int or expected_count != planned_count
            or type(cutoff) is not int or cutoff != rows[-1][1]):
        raise RuntimeError('Original-Snapshot und urspruenglicher Paketplan widersprechen sich.')
    ids = list(current_ids)
    if (any(type(uid) is not int or not 1 <= uid <= 4294967295 for uid in ids)
            or ids != sorted(set(ids))):
        raise RuntimeError('Aktuelle Quell-UIDs sind ungueltig, doppelt oder nicht aufsteigend.')
    allowed = tuple(allowed_missing)
    if (any(type(uid) is not int or not 1 <= uid <= 4294967295 for uid in allowed)
            or len(set(allowed)) != len(allowed)):
        raise RuntimeError('Ungueltige Liste explizit bestaetigter Quell-Luecken.')
    split = bisect.bisect_right(ids, cutoff)
    old = ids[:split]
    new_count = len(ids) - split
    original_hash = state['source_uid_sha256']
    if len(old) == expected_count and _digest_uids(old) == original_hash:
        original = old
        missing = ()
    else:
        present = set(old)
        missing = tuple(sorted(uid for uid in allowed if uid <= cutoff and uid not in present))
        original = sorted(old + list(missing))
        if (len(original) != expected_count
                or _digest_uids(original) != original_hash):
            raise RuntimeError('Quell-Snapshot weicht ueber die ausdruecklich bestaetigten '
                               'UID-Luecken hinaus ab. Original-Hash bleibt unveraendert.')
    covered = 0
    for start, end, expected in rows:
        actual = bisect.bisect_right(original, end) - bisect.bisect_left(original, start)
        if actual != expected:
            raise RuntimeError('Rekonstruierte Original-UIDs passen nicht zu den alten Paketgrenzen.')
        covered += actual
    if covered != len(original):
        raise RuntimeError('Original-UIDs liegen ausserhalb des urspruenglichen Paketplans.')
    return original, missing, new_count


def count_verified_progress(state, rows):
    """Count completed packets plus selected messages in open checkpoints.

    A packet with an unavailable source UID stays outside completed; any
    available_processed marker is deliberately ignored here. Only its actual
    selected total is counted, never the unavailable message. These transfer
    checkpoints still are not an independent proof of target message bodies.
    Legacy chunk counters are used only if no totals entry exists for a packet.
    """
    planned_count = _validate_rows(rows)
    completed = state.get('completed', [])
    if any(type(index) is not int or not 0 <= index < len(rows) for index in completed):
        raise RuntimeError('Ungueltiger Index eines abgeschlossenen Pakets.')
    done = set(completed)
    totals = state.get('safe_chunk_totals', {})
    checkpoints = state.get('safe_chunk_next', {})
    if not isinstance(totals, dict) or not isinstance(checkpoints, dict):
        raise RuntimeError('Teilpaket-Fortschritt hat ein ungueltiges Format.')
    count = sum(rows[index][2] for index in done)
    for index, (_, _, expected) in enumerate(rows):
        if index in done:
            continue
        key = str(index)
        if key in totals:
            item = totals[key]
            if not isinstance(item, dict) or 'selected' not in item:
                raise RuntimeError(f'Paket {index+1}: quittierte selected-Summe fehlt.')
            selected = _nonnegative_integer(item['selected'], f'Paket {index+1}: selected')
            if selected > expected:
                raise RuntimeError(f'Paket {index+1}: selected-Summe groesser als Paket.')
            count += selected
        else:
            chunks = _nonnegative_integer(checkpoints.get(key, 0),
                                          f'Paket {index+1}: Teilpaketzahl')
            if chunks > (expected + LEGACY_CHUNK_SIZE - 1) // LEGACY_CHUNK_SIZE:
                raise RuntimeError(f'Paket {index+1}: Teilpaketzahl groesser als Paket.')
            count += min(chunks * LEGACY_CHUNK_SIZE, expected)
    if count > planned_count:
        raise RuntimeError('Quittierter Fortschritt ist groesser als der Originalplan.')
    return count



def backup_state_before_v28():
    """Preserve the exact previous state bytes in a new private file."""
    backup_dir = ROOT / 'backups'
    secure_dir(backup_dir)
    original = STATE.read_bytes()
    fd, backup = tempfile.mkstemp(prefix='migration-before-v28-', suffix='.json', dir=backup_dir)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    return backup


def validate_gap_checkpoints(state, rows, chunks_by_packet, missing):
    """Never reuse an unavailable checkpoint if that source UID reappears."""
    unavailable = set(missing)
    completed = set(state['completed'])
    partial = state.get('available_processed', [])
    if (not isinstance(partial, list) or any(type(i) is not int or not 0 <= i < len(rows)
                                           for i in partial)
            or len(set(partial)) != len(partial) or completed.intersection(partial)):
        raise RuntimeError('Ungueltige Liste nur verfuegbar abgearbeiteter Pakete.')
    totals_by_packet = state.get('safe_chunk_totals', {})
    for key, totals in totals_by_packet.items():
        recorded = totals.get('unavailable_uids', [])
        if (not isinstance(recorded, list) or any(type(uid) is not int for uid in recorded)
                or len(set(recorded)) != len(recorded)
                or totals.get('unavailable_source', 0) != len(recorded)):
            raise RuntimeError('Ungueltiger Checkpoint fuer fehlende Quell-UIDs.')
        if set(recorded) - unavailable:
            raise RuntimeError('Eine zuvor ausgelassene Quell-UID ist wieder vorhanden. '
                               'Separater Abgleich erforderlich; keine Mail still ueberspringen.')
    for uid in missing:
        idx = next((i for i, (start, end, _) in enumerate(rows) if start <= uid <= end), None)
        if idx is None or idx in completed:
            raise RuntimeError('Fehlende Quell-UID betrifft einen bereits abgeschlossenen/unbekannten Bereich; '
                               'Archivnachweis separat pruefen.')
        chunk_index = next(i for i, chunk in enumerate(chunks_by_packet[idx]) if uid in chunk)
        previous = int(state.get('safe_chunk_next', {}).get(str(idx), 0))
        recorded = totals_by_packet.get(str(idx), {}).get('unavailable_uids', [])
        if previous > chunk_index and uid not in recorded:
            raise RuntimeError('Fehlende Quell-UID liegt in einem bereits quittierten Teilpaket; '
                               'Archivnachweis separat pruefen.')
    for idx in partial:
        totals = totals_by_packet.get(str(idx), {})
        expected_missing = sorted(uid for uid in missing if rows[idx][0] <= uid <= rows[idx][1])
        if (not expected_missing or sorted(totals.get('unavailable_uids', [])) != expected_missing
                or totals.get('selected', 0) + len(expected_missing) != rows[idx][2]
                or totals.get('transferred', 0) + totals.get('skipped', 0) != totals.get('selected')
                or int(state.get('safe_chunk_next', {}).get(str(idx), 0)) != len(chunks_by_packet[idx])):
            raise RuntimeError('Checkpoint eines Pakets mit offener Quell-Luecke ist unvollstaendig.')





LANE_PLAN_VERSION = 1
LANE_PLAN_FIELD = 'cache_lane_plan'
LOG_PACKET_PATTERN = re.compile(r'^p([0-9]+)-([0-9]+)-w([0-9]+)(?:[-.]|$)')
CACHE_UID_PATTERN = re.compile(r'^([0-9]+)_([0-9]+)$')


def _legacy_lane(index, count):
    return 0 if index < (count + 1) // 2 else 1


def _validate_plan_rows(state, rows):
    if not rows:
        raise RuntimeError('Kein Paketplan fuer Cache-Zuordnung vorhanden.')
    last = 0
    for start, end, count in rows:
        if (any(type(value) is not int for value in (start, end, count))
                or start <= last or end < start or end > 4294967295
                or count < 1 or count > 2000 or count > end - start + 1):
            raise RuntimeError('Ungueltiger Paketplan fuer Cache-Zuordnung.')
        last = end
    manifest = ''.join(f'{start}\t{end}\t{count}\n' for start, end, count in rows)
    expected = hashlib.sha256(manifest.encode('utf-8')).hexdigest()
    if state.get('manifest_sha256') != expected:
        raise RuntimeError('Cache-Zuordnung und unveraenderter Manifest-Hash passen nicht zusammen.')
    if (state.get('snapshot_count') != sum(row[2] for row in rows)
            or state.get('snapshot_max_uid') != rows[-1][1]):
        raise RuntimeError('Cache-Zuordnung passt nicht zum urspruenglichen Snapshot.')
    source_hash = state.get('source_uid_sha256')
    if not isinstance(source_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', source_hash):
        raise RuntimeError('Ungueltiger Original-UID-Hash fuer Cache-Zuordnung.')


def _packet_index(value, count):
    if type(value) is int:
        index = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        index = int(value)
        if str(index) != value:
            raise RuntimeError('Nicht eindeutiger Paketindex im Migrationszustand.')
    else:
        raise RuntimeError('Unlesbarer Paketindex im Migrationszustand.')
    if not 0 <= index < count:
        raise RuntimeError('Paketindex liegt ausserhalb des Originalplans.')
    return index


def _state_touch_evidence(state, count):
    """Presence is evidence, even attempts=0 or safe_chunk_next=0."""
    touched = set()
    for key in ('completed', 'available_processed'):
        values = state.get(key, [])
        if not isinstance(values, list):
            raise RuntimeError(f'Ungueltige Paketliste: {key}.')
        touched.update(_packet_index(value, count) for value in values)
    for key in ('results', 'attempts', 'safe_chunk_next', 'safe_chunk_totals', 'probe_results'):
        values = state.get(key, {})
        if not isinstance(values, dict):
            raise RuntimeError(f'Ungueltige Paketnachweise: {key}.')
        touched.update(_packet_index(value, count) for value in values)
    progress = state.get('in_progress', {})
    if not isinstance(progress, dict):
        raise RuntimeError('Ungueltige laufende Paketzuordnung.')
    lane_evidence = []
    for lane_key, values in progress.items():
        lane = _packet_index(lane_key, 4)
        if not isinstance(values, list):
            raise RuntimeError('Ungueltige laufende Paketliste.')
        for value in values:
            index = _packet_index(value, count)
            touched.add(index)
            lane_evidence.append((index, lane))
    return touched, lane_evidence


def _walk_evidence_files(directory):
    """Yield files without following symlinks or silently suppressing I/O errors."""
    directory = Path(directory)
    if directory.is_symlink():
        raise RuntimeError('Beweisverzeichnis darf kein Symlink sein.')
    if not directory.exists():
        return
    if not directory.is_dir():
        raise RuntimeError('Beweisverzeichnis ist kein Verzeichnis.')

    def failed(error):
        raise RuntimeError('Log-/Cache-Nachweise konnten nicht vollstaendig gelesen werden.') from error

    for current, dirs, files in os.walk(directory, followlinks=False, onerror=failed):
        for name in dirs:
            if (Path(current) / name).is_symlink():
                raise RuntimeError('Symlink in Log-/Cache-Nachweisen; keine Neuverteilung.')
        for name in files:
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                raise RuntimeError('Unklarer Dateityp in Log-/Cache-Nachweisen.')
            if name == '.DS_Store':
                continue  # Finder metadata cannot be an imapsync UID mapping or log.
            yield path


def _log_evidence(logs_dir, count):
    owned = set()
    unknown = False
    files = 0
    for path in _walk_evidence_files(logs_dir):
        files += 1
        match = LOG_PACKET_PATTERN.match(path.name)
        if not match:
            unknown = True
            continue
        first, last, worker = map(int, match.groups())
        if not (1 <= first <= last <= count and 1 <= worker <= 4):
            raise RuntimeError('Log nennt einen ungueltigen Paketbereich oder Worker.')
        # File creation precedes APPEND, so even an empty/dry/failed log pins it.
        owned.update((index, worker - 1) for index in range(first - 1, last))
    return owned, unknown, files


def _cache_evidence(root, rows):
    starts = [row[0] for row in rows]
    owned = set()
    uncertain = set()
    files = 0
    for lane in range(4):
        parent = Path(root) / f'cache-worker{lane+1}'
        if parent.is_symlink():
            raise RuntimeError('Cache-Lane darf kein Symlink sein.')
        directory = parent / 'imapsync_cache'
        for path in _walk_evidence_files(directory):
            files += 1
            match = CACHE_UID_PATTERN.fullmatch(path.name)
            if not match:
                uncertain.add(lane)
                continue
            source_uid, target_uid = map(int, match.groups())
            if not (1 <= source_uid <= 4294967295 and 1 <= target_uid <= 4294967295):
                uncertain.add(lane)
                continue
            index = bisect.bisect_right(starts, source_uid) - 1
            if index < 0 or source_uid > rows[index][1]:
                uncertain.add(lane)
                continue
            owned.add((index, lane))
    return owned, uncertain, files


def _pending_messages(state, rows, index):
    if index in set(state.get('completed', [])) | set(state.get('available_processed', [])):
        return 0
    expected = rows[index][2]
    totals = state.get('safe_chunk_totals', {})
    key = str(index)
    if key in totals:
        item = totals[key]
        if not isinstance(item, dict) or type(item.get('selected')) is not int:
            raise RuntimeError('Teilpaketsumme fuer Lastverteilung ist ungueltig.')
        selected = item['selected']
        if not 0 <= selected <= expected:
            raise RuntimeError('Teilpaketsumme fuer Lastverteilung liegt ausserhalb des Pakets.')
    else:
        chunks = state.get('safe_chunk_next', {}).get(key, 0)
        if type(chunks) is not int or not 0 <= chunks <= (expected + 199) // 200:
            raise RuntimeError('Teilpaketzaehler fuer Lastverteilung ist ungueltig.')
        selected = min(chunks * 200, expected)
    return expected - selected


def lane_plan_digest(metadata):
    payload = {key: value for key, value in metadata.items() if key != 'mapping_sha256'}
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return hashlib.sha256(encoded).hexdigest()


def _validate_stored_plan(state, rows, metadata):
    if not isinstance(metadata, dict):
        raise RuntimeError('Gespeicherte Cache-Zuordnung ist unlesbar.')
    count = len(rows)
    if (metadata.get('version') != LANE_PLAN_VERSION
            or metadata.get('manifest_sha256') != state['manifest_sha256']
            or metadata.get('source_uid_sha256') != state['source_uid_sha256']
            or metadata.get('packet_count') != count):
        raise RuntimeError('Gespeicherte Cache-Zuordnung gehoert nicht zum Originalplan.')
    mapping = metadata.get('mapping')
    if (not isinstance(mapping, dict) or set(mapping) != {str(index) for index in range(count)}
            or any(type(lane) is not int or lane not in range(4) for lane in mapping.values())):
        raise RuntimeError('Gespeicherte Cache-Zuordnung ist unvollstaendig oder ungueltig.')
    if metadata.get('mapping_sha256') != lane_plan_digest(metadata):
        raise RuntimeError('Pruefsumme der festen Cache-Zuordnung stimmt nicht.')
    high_water = metadata.get('legacy_high_water')
    if not isinstance(high_water, dict) or set(high_water) != {'0', '1'}:
        raise RuntimeError('Gespeicherte Altfortschrittsgrenzen fehlen.')
    split = (count + 1) // 2
    for lane, start, end in ((0, 0, split), (1, split, count)):
        high = high_water[str(lane)]
        if type(high) is not int or not start - 1 <= high < end:
            raise RuntimeError('Gespeicherte Altfortschrittsgrenze ist ungueltig.')
        tail_started = False
        for index in range(start, end):
            owner = mapping[str(index)]
            if owner not in (lane, lane + 2) or (index <= high and owner != lane):
                raise RuntimeError('Gespeicherte Zuordnung verschiebt bereits beruehrte Alt-Pakete.')
            if owner == lane + 2:
                tail_started = True
            elif tail_started:
                raise RuntimeError('Gespeicherte neue Cache-Lane ist kein zusammenhaengender Restbereich.')
    return dict(mapping)


def build_or_validate_lane_plan(state, rows, logs_dir, root):
    """Return immutable mapping and metadata; the caller atomically saves them.

    Mapping keys are canonical zero-based packet strings; values are cache
    lanes 0..3. Worker concurrency is deliberately absent from this function.
    """
    _validate_plan_rows(state, rows)
    schema = state.get('schema')
    if schema not in (2, 3):
        raise RuntimeError('Unbekanntes Statusschema fuer feste Cache-Zuordnung.')
    count = len(rows)
    touched, state_owned = _state_touch_evidence(state, count)
    log_owned, unknown_log, log_files = _log_evidence(logs_dir, count)
    cache_owned, uncertain_cache, cache_files = _cache_evidence(root, rows)
    owned = set(state_owned) | log_owned | cache_owned
    if LANE_PLAN_FIELD in state:
        metadata = state[LANE_PLAN_FIELD]
        mapping = _validate_stored_plan(state, rows, metadata)
        for index, lane in owned:
            if mapping[str(index)] != lane:
                raise RuntimeError('Log-/Cache-Nachweis widerspricht der festen Paketzuordnung.')
        if unknown_log and any(mapping[str(index)] != _legacy_lane(index, count) for index in range(count)):
            raise RuntimeError('Unbekannte Lognachweise verhindern die sichere feste Cache-Zuordnung.')
        for lane in uncertain_cache:
            if lane >= 2 or any(mapping[str(index)] != lane for index in range(count)
                                if _legacy_lane(index, count) == lane):
                raise RuntimeError('Unbekannter Cache-Inhalt verhindert sichere Wiederaufnahme.')
        return mapping, copy.deepcopy(metadata)
    if schema == 3:
        raise RuntimeError('Schema 3 ohne feste Cache-Zuordnung; kein Neuplanen erlaubt.')

    split = (count + 1) // 2
    high_water = {0: -1, 1: split - 1}
    conservative = set()
    for index in touched:
        lane = _legacy_lane(index, count)
        high_water[lane] = max(high_water[lane], index)
    for index, lane in owned:
        if lane != _legacy_lane(index, count):
            raise RuntimeError('Alter Log-/Cache-Nachweis liegt in einer unerwarteten Cache-Lane.')
        high_water[lane] = max(high_water[lane], index)
    if uncertain_cache.intersection({2, 3}):
        raise RuntimeError('Neue Cache-Lane besitzt Daten ohne gespeicherte Zuordnung.')
    if unknown_log:
        conservative.update((0, 1))
    conservative.update(uncertain_cache)
    for lane in conservative:
        high_water[lane] = (split - 1) if lane == 0 else (count - 1)

    mapping = {str(index): _legacy_lane(index, count) for index in range(count)}
    pending = [_pending_messages(state, rows, index) for index in range(count)]
    for lane, start, end in ((0, 0, split), (1, split, count)):
        tail = list(range(high_water[lane] + 1, end))
        fixed_load = sum(pending[index] for index in range(start, high_water[lane] + 1))
        tail_load = sum(pending[index] for index in tail)
        choices = []
        old_tail = 0
        for cut in range(len(tail) + 1):
            old_load, new_load = fixed_load + old_tail, tail_load - old_tail
            # Prefer retaining more packets in the old cache when equally balanced.
            choices.append((abs(old_load - new_load), -cut, cut))
            if cut < len(tail):
                old_tail += pending[tail[cut]]
        cut = min(choices)[2]
        for index in tail[cut:]:
            mapping[str(index)] = lane + 2
    metadata = dict(version=LANE_PLAN_VERSION,
        manifest_sha256=state['manifest_sha256'], source_uid_sha256=state['source_uid_sha256'],
        packet_count=count, mapping=dict(mapping),
        legacy_high_water={str(lane): high for lane, high in high_water.items()},
        evidence_counts=dict(state_packets=len(touched), log_files=log_files, cache_files=cache_files),
        conservative_legacy_lanes=sorted(conservative),
        estimated_pending_at_creation={str(lane): sum(pending[index] for index in range(count)
            if mapping[str(index)] == lane) for lane in range(4)})
    metadata['mapping_sha256'] = lane_plan_digest(metadata)
    _validate_stored_plan(state, rows, metadata)
    return mapping, metadata


def run_two_production(password: str, workers: int = 4, memory_guard: ContinuousMemoryMonitor | None = None,
                       parallel_controller=None):
    """Bis zu vier produktive Cache-Worker mit festen Cache-Lanes und Checkpoints.

    Bewahrt alle V2.2-UID-Caches, Paketnummern, UIDVALIDITY und den Manifest-Hash.
    Ein abgeschlossenes Teilpaket wird erst NACH Logpruefung atomar quittiert.
    """
    global ACTIVE_CACHE_LANES
    ACTIVE_CACHE_LANES = None
    if isinstance(workers, bool) or workers not in (1, 2, 3, 4):
        raise ValueError('Ein bis vier gleichzeitige Transfers zulaessig')
    if memory_guard is None:
        memory_guard = ContinuousMemoryMonitor(workers=workers)
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
    for lane in (1, 2, 3, 4):
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
    print(f'Zielbestand: {actual_target} Nachrichten; durch Status mindestens {baseline} erwartet.',
          flush=True)
    if actual_target < baseline:
        raise RuntimeError('Zielbestand kleiner als bereits quittiert. Keine weitere Migration!')
    if actual_target > baseline:
        print('WARNUNG: Zielbestand groesser als quittiert (z.B. nach unterbrochenem APPEND). '
              'UID-Cache erhalten; spaeter Vollstaendigkeitsaudit zwingend.', flush=True)

    print('Lese Quell-UID-Liste und pruefe den ORIGINAL-Snapshot einschliesslich bekannter Luecke ...', flush=True)
    m = source(password)
    try:
        if uidvalidity(m) != state['uidvalidity1']:
            raise RuntimeError('UIDVALIDITY der aktuellen Quellverbindung geaendert!')
        current_ids = source_uids(m)
    finally:
        m.logout()
    snapshot, missing, new_uids = verify_original_snapshot(state, rows, current_ids)
    chunks_by_packet = packet_uid_chunks(snapshot, rows, SAFE_CHUNK)
    validate_gap_checkpoints(state, rows, chunks_by_packet, missing)
    missing_set = set(missing)
    print(f'ORIGINAL-Snapshot bestaetigt: {len(snapshot)} geplante UIDs; '
          f'{len(snapshot)-len(missing)} derzeit vorhanden; {new_uids} neue UIDs separat.', flush=True)
    if missing:
        print('OFFENE ARCHIVIERUNGSLUECKE: Quell-UID ' + ', '.join(map(str, missing)) +
              '. Uebrige Mails werden kopiert; diese UID gilt NICHT als uebertragen.', flush=True)
    print('Pruefe alte Logs und UID-Caches fuer dauerhafte Paket-Zuordnung ...', flush=True)
    mapping, lane_metadata = build_or_validate_lane_plan(state, rows, LOGS, ROOT)
    pending_indices = set(range(len(rows))) - set(state['completed']) - set(state.get('available_processed', []))
    pending_lanes = {mapping[str(index)] for index in pending_indices}
    effective_max = min(workers, max(1, len(pending_lanes)))
    prior_runtime = state.get('v29_runtime', {})
    prior_safety = prior_runtime.get('safety_limit')
    if prior_runtime.get('safety_limited') and type(prior_safety) is int and 1 <= prior_safety <= 4:
        effective_max = min(effective_max, prior_safety)
        print(f'Gespeicherter Sicherheitsrueckfall: hoechstens {effective_max} Transfers; kein erneuter Hochlastversuch.', flush=True)
    controller = parallel_controller or AdaptiveParallelism(max_workers=effective_max)
    if controller.max_workers > workers:
        raise RuntimeError('Controller verlangt mehr Parallelitaet als angefordert')
    if prior_runtime.get('safety_limited') and prior_safety in (1, 2):
        controller.degrade(prior_runtime.get('safety_reason') or 'Gespeicherter Sicherheitsrueckfall', limit=prior_safety)
    memory_guard.parallel_controller = controller
    if lane_metadata.get('conservative_legacy_lanes'):
        print('Unklare alte Nachweise: betroffene Cache-Bereiche bleiben vorsorglich unveraendert.', flush=True)
    print(f'Cache-Lanes mit offener Arbeit: {len(pending_lanes)}; Start mit hoechstens {controller.limit} Transfers; '
          f'Messfenster je Stufe ca. {controller.stage_seconds:.0f}s, alle Kopien produktiv.', flush=True)
    safety = '7,5 GiB je Worker / 10 GiB gemeinsam WEICH; bei Bedarf kuenftige Parallelitaet senken'
    print(f'Produktivlauf: {workers} Worker, maximal {SAFE_CHUNK} Nachrichten je Teilpaket, '
          f'Schutz: {safety}. '
          f'Vorhandene {sum(rows[i][2] for i in state["completed"])} '
          f'quittierte Nachrichten bleiben unveraendert.', flush=True)

    secure_dir(LOGS)
    fd, passpath = tempfile.mkstemp(prefix='.pass-', dir=ROOT)
    os.fchmod(fd, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(password + '\n')
        pwfile = Path(passpath)
        session = time.strftime('%Y%m%d-%H%M%S') + f'-{os.getpid()}'
        started = time.monotonic()
        if state['schema'] == 2:
            backup_state_before_v29()
        state['schema'] = 3
        state['cache_lane_plan'] = lane_metadata
        state['continuation_version'] = '2.9'
        state.setdefault('available_processed', [])
        gap_details = {}
        for uid in missing:
            idx = next(i for i, row in enumerate(rows) if row[0] <= uid <= row[1])
            gap_details[str(uid)] = dict(status='OFFEN', packet_index=idx,
                reason='Quelle nicht vorhanden; Archivkopie nicht nachgewiesen',
                evidence='Original-UID-Snapshot durch unveraenderten SHA-256 bestaetigt')
        state['missing_source'] = gap_details
        state.setdefault('safe_chunk_size', SAFE_CHUNK)
        state.setdefault('safe_chunk_next', {})
        state.setdefault('safe_chunk_totals', {})
        state['requested_workers'] = workers
        state['memory_policy'] = 'v2.9-staged-four-soft-budget'
        state['adaptive_single_worker'] = controller.limit == 1
        state['adaptive_switch_reason'] = 'V2.9: produktive Stufenmessung mit festen Cache-Lanes'
        state['v29_runtime'] = controller.snapshot()
        state['adaptive_switch_time'] = time.strftime('%Y-%m-%d %H:%M:%S %z')
        save_state(state)
        ACTIVE_CACHE_LANES = dict(mapping)

        with WorkerRunControl() as control:
            gate = ChunkConcurrencyGate(controller)
            control.gate = gate

            def one_lane(lane):
                for idx in range(len(rows)):
                    if (mapping[str(idx)] != lane or idx in state['completed']
                            or idx in state['available_processed']):
                        continue
                    if control.stop_event.is_set() or control.drain_event.is_set():
                        return
                    pieces = chunks_by_packet[idx]
                    with LOCK:
                        completed_chunks = int(state['safe_chunk_next'].get(str(idx), 0))
                        if not 0 <= completed_chunks <= len(pieces):
                            raise RuntimeError(f'Paket {idx+1}: ungueltiger Teilpaket-Checkpoint')
                    for subindex in range(completed_chunks, len(pieces)):
                        if not gate.acquire(lane, control.stop_event, control.drain_event):
                            return
                        checkpointed = False
                        transfer_started = False
                        stats = None
                        try:
                            if control.stop_event.is_set() or control.drain_event.is_set():
                                return
                            with LOCK:
                                state.setdefault('in_progress', {})[str(lane)] = [idx]
                                save_state(state)
                            transfer_started = True
                            original_ids = pieces[subindex]
                            absent = [uid for uid in original_ids if uid in missing_set]
                            ids = [uid for uid in original_ids if uid not in missing_set]
                            if not ids:
                                raise RuntimeError('Ganzes Teilpaket fehlt in Quelle; separate Klaerung erforderlich.')
                            suffix = f'-safe-c{subindex+1:02d}-{session}'
                            ok, stats, attempts = execute_group(
                                [idx], lane, rows, pwfile, uid_range=(ids[0], ids[-1]),
                                expected_override=len(ids), log_suffix=suffix,
                                stop_event=control.stop_event, memory_guard=memory_guard)
                            if not ok:
                                raise RuntimeError(f'Paket {idx+1} Teil {subindex+1}: '
                                                   f'Fehler in {stats["log"]}')
                            with LOCK:
                                if state['safe_chunk_next'].get(str(idx), 0) != subindex:
                                    raise RuntimeError(f'Paket {idx+1}: nichtmonotones Teilpaket-Checkpoint')
                                running = state['safe_chunk_totals'].setdefault(str(idx), {
                                    'transferred':0, 'skipped':0, 'selected':0, 'duration_seconds':0.0,
                                    'peak_rss_mib':0.0, 'chunks':0})
                                running.setdefault('unavailable_source', 0)
                                running.setdefault('unavailable_uids', [])
                                # Initialise from the OLD selected sum before adding this chunk.
                                running.setdefault('planned_selected', running['selected'] + running['unavailable_source'])
                                if set(absent).intersection(running['unavailable_uids']):
                                    raise RuntimeError('Quell-Luecke wuerde doppelt quittiert.')
                                running['transferred'] += stats['transferred']
                                running['skipped'] += stats['skipped']
                                running['selected'] += stats['selected']
                                running['planned_selected'] += len(original_ids)
                                running['unavailable_source'] += len(absent)
                                running['unavailable_uids'].extend(absent)
                                running['chunks'] += 1
                                running['duration_seconds'] += stats['duration_seconds']
                                running['peak_rss_mib'] = max(running['peak_rss_mib'], stats['peak_rss_mib'] or 0)
                                running['last_log'] = stats['log']
                                state['safe_chunk_next'][str(idx)] = subindex + 1
                                state['attempts'][str(idx)] = state['attempts'].get(str(idx), 0) + attempts
                                if memory_guard.serial_requested.is_set():
                                    state['adaptive_single_worker'] = True
                                    state['adaptive_switch_reason'] = memory_guard.serial_reason
                                save_state(state)
                                checkpointed = True
                        finally:
                            copied = (stats.get('measured_copies', stats['transferred'])
                                      if checkpointed else 0)
                            copied_bytes = stats.get('copied_bytes') if checkpointed else None
                            gate.release(lane, transferred=copied, copied_bytes=copied_bytes,
                                         successful=checkpointed or not transfer_started)
                            if checkpointed:
                                with LOCK:
                                    state['v29_runtime'] = controller.snapshot()
                                    state['adaptive_single_worker'] = controller.limit == 1
                                    save_state(state)
                    with LOCK:
                        totals = state['safe_chunk_totals'][str(idx)]
                        gap_uids = sorted(uid for uid in missing if rows[idx][0] <= uid <= rows[idx][1])
                        unavailable = totals.get('unavailable_source', 0)
                        if (totals['selected'] + unavailable != rows[idx][2] or
                            totals.get('planned_selected', totals['selected']) != rows[idx][2] or
                            totals['transferred'] + totals['skipped'] != totals['selected'] or
                            sorted(totals.get('unavailable_uids', [])) != gap_uids or
                            unavailable != len(gap_uids) or
                            state['safe_chunk_next'][str(idx)] != len(pieces)):
                            raise RuntimeError(f'Paket {idx+1}: Teilpaketsumme falsch: {totals}')
                        if gap_uids:
                            if idx not in state['available_processed']:
                                state['available_processed'].append(idx)
                                state['available_processed'].sort()
                            # Deliberately NOT added to completed and no successful full result.
                            label = 'VORHANDENE BEARBEITET; ARCHIVLUECKE OFFEN'
                        else:
                            if idx not in state['completed']:
                                state['completed'].append(idx)
                                state['completed'].sort()
                            state['results'][str(idx)] = dict(totals,
                                errors=0, missing=0, return_value=0,
                                peak_rss_mib=totals['peak_rss_mib'],
                                log=totals.get('last_log'), expected=rows[idx][2])
                            label = 'OK'
                        state['in_progress'][str(lane)] = []
                        save_state(state)
                        total_done = count_verified_progress(state, rows)
                        duration = time.monotonic() - started
                        print(f'[{time.strftime("%H:%M:%S")}] PAKET {idx+1}/{len(rows)} {label} '
                              f'| Worker {lane+1} | {total_done}/{state["snapshot_count"]} '
                              f'quittiert | Gesamtlaufzeit {format_elapsed(duration)}', flush=True)

            def guarded_lane(lane):
                try:
                    one_lane(lane)
                except BaseException:
                    control.stop_event.set()
                    gate.wake_all()
                    raise

            # Four permanent cache owners remain reachable even at concurrency one.
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    futures = []
                    try:
                        futures = [pool.submit(guarded_lane, lane) for lane in range(4)]
                        for future in concurrent.futures.as_completed(futures):
                            future.result()
                    except BaseException:
                        control.stop_event.set()
                        gate.wake_all()
                        raise
            finally:
                # The executor has joined every child. Save a safety reduction even
                # if no chunk succeeded, without acknowledging unsaved mail counts.
                original_error = sys.exc_info()[0] is not None
                try:
                    with LOCK:
                        durable = load_state()
                        durable['v29_runtime'] = controller.snapshot()
                        durable['adaptive_single_worker'] = controller.limit == 1
                        save_state(durable)
                except Exception:
                    if not original_error:
                        raise
                    print('WARNUNG: Sicherheitsrueckfall konnte nicht gespeichert werden; '
                          'urspruenglicher Transferfehler bleibt erhalten.', file=sys.stderr, flush=True)
            if control.stop_event.is_set():
                raise RuntimeError('Produktivlauf unterbrochen. Status und UID-Caches bleiben erhalten.')
            available_done = set(state['completed']) | set(state['available_processed'])
            if control.drain_event.is_set() and available_done != set(range(len(rows))):
                print('KONTROLLIERT ANGEHALTEN: laufende Teilpakete quittiert; '
                      'mit recover aus dem gespeicherten Zustand fortsetzen.', flush=True)
                return
            if available_done != set(range(len(rows))):
                raise RuntimeError('Nicht alle verfuegbaren Pakete abgearbeitet; bitte status und Logs pruefen')
            if state['missing_source']:
                total_done = count_verified_progress(state, rows)
                print(f'ALLE {total_done} VERFUEGBAREN SNAPSHOT-MAILS BEARBEITET. '
                      f'{len(state["missing_source"])} ARCHIVIERUNGSLUECKE(N) BLEIBEN OFFEN: '
                      + ', '.join(state['missing_source']) + '. KEIN VOLLSTAENDIGER ABSCHLUSS.', flush=True)
                print('Die fehlende Mail separat klaeren; abschliessender Archivabgleich bleibt erforderlich.', flush=True)
            else:
                print('ALLE SNAPSHOT-PAKETE UEBERTRAGEN. '
                      'Jetzt gesondert audit ausfuehren. Neu eingetroffene Quellnachrichten separat nachziehen.', flush=True)
    finally:
        os.unlink(passpath)







def recover_parallel(password: str, workers: int = 4) -> None:
    monitor = ContinuousMemoryMonitor(workers=workers)
    print(f'DAUERLAUF V2.9: bis zu {workers} gleichzeitige Transfers; '
          'dauerhafte Cache-Zuordnung fuer bis zu vier Worker. '
          'Produktive Messung startet mit hoechstens zwei Transfers und prueft danach 3/4. '
          'LC_MESSAGES=C; RAM-Schwellen 7,5 GiB einzeln / 10 GiB gesamt bleiben weich.', flush=True)
    run_two_production(password, workers=workers, memory_guard=monitor)



def do_memcheck():
    print('macOS-Speicher:', describe_memory(mac_memory_sample()))
    print('V2.9: 7,5 GiB je Worker / 10 GiB gemeinsam sind weiche Schwellen. '
          'Bei Ueberschreitung oder kritischem Druck nach aktuellem Teilpaket seriell weiter.')





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
    print(f'Ziel-INBOX Nachrichten: {target_count} (Soll fuer Snapshot: {state["snapshot_count"]})')
    if state.get('missing_source'):
        print('OFFENE ARCHIVIERUNGSLUECKE:', ', '.join(state['missing_source']))
        raise RuntimeError('Kein vollstaendiger Abschluss: fehlende Quell-Mail noch nicht im Archiv nachgewiesen.')
    if stable and complete and exact_count:
        print('BESTANDSAUDIT OK. Kein kryptografischer Vollinhaltvergleich; Stichproben empfohlen.')
    else:
        raise RuntimeError('Bestandsaudit NICHT bestanden. Keine Loeschung/kein Abschluss!')


def do_status():
    state = load_state()
    rows = batches()
    done = set(state['completed'])
    n_done = sum(rows[i][2] for i in done)
    total = count_verified_progress(state, rows)
    print(f'Erledigt: {len(done)}/{len(rows)} Pakete; {n_done}/{state["snapshot_count"]} Nachrichten')
    print(f'Einschliesslich quittierter Teilpakete: {total}/{state["snapshot_count"]} '
          f'({100*total/state["snapshot_count"]:.4f}%); nicht quittiert {state["snapshot_count"]-total}')
    print(f'Pilot kontrolliert: {state.get("pilot_checked", False)} | '
          f'Kurze Parallelprobe bestanden: {state.get("parallel_probed", False)}')
    if state.get('missing_source'):
        print('OFFENE QUELL-/ARCHIVIERUNGSLUECKEN:', ', '.join(state['missing_source']))
        print('Fehlende UIDs werden NICHT als uebertragen oder vollstaendig archiviert gezaehlt.')
    runtime = state.get('v29_runtime', {})
    print('V2.9: bis zu vier Cache-Worker; 7,5/10 GiB weiche Schwellen; Locale-Fix.')
    print('Gespeicherte maximale Parallelitaet:', state.get('requested_workers', 'aeltere Version'))
    if runtime:
        phases = {'baseline': 'Ausgangsmessung', 'candidate': 'Vergleichsmessung',
                  'selected': 'Messvergleich abgeschlossen', 'frozen': 'niedrigere Stufe beibehalten',
                  'fixed': 'feste Obergrenze', 'safety-limited': 'Sicherheitsrueckfall',
                  'error-limited': 'Rueckfall nach Transferfehler'}
        print(f'Zuletzt gewaehlte Parallelitaet: {runtime.get("selected_workers", "?")} | '
              f'Phase: {phases.get(runtime.get("phase"), runtime.get("phase", "?"))}')
        for entry in runtime.get('history', []):
            rate = entry.get('messages_per_second')
            if isinstance(rate, (int, float)):
                print(f'  Messstufe {entry["workers"]}: {rate:.2f} Mails/s, '
                      f'{entry["transferred"]} neue Kopien in {entry["elapsed_seconds"]:.0f}s; '
                      f'Entscheidung: {entry.get("decision", "offen")}')
        if runtime.get('safety_limited'):
            print('Gespeicherter Sicherheitsrueckfall:', runtime.get('safety_reason', 'ja'))
    else:
        print('Vier-Worker-Erweiterung noch nicht aktiviert; bisheriger Zustand unveraendert.')
    print('Gespeicherter Status; keine Live-Abfrage laufender Prozesse.')
    if any(state.get('in_progress', {}).values()):
        print('Begonnene, noch offene Pakete:', state['in_progress'])
    if done:
        largest_peak = max((state['results'][str(i)].get('peak_rss_mib') or 0) for i in done)
        print(f'Historischer Prozess-RSS-Hoechstwert: {largest_peak:.0f} MiB (kein Live-Wert)')
    chunks = state.get('safe_chunk_next', {})
    print('Teilpaketfortschritt in offenen Paketen:',
          ', '.join(f'{int(idx)+1}:{pos}' for idx, pos in sorted(chunks.items(), key=lambda p:int(p[0]))
                    if int(idx) not in done) or 'keine')
    print('Status:', STATE)
    if state['schema'] == 3:
        print('Fortsetzung und Status ab jetzt mit V2.9; alte Versionen akzeptieren dieses Schema nicht.')


def _legacy_selftest():
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
    assert lane_for(0,125) == 0 and lane_for(62,125) == 0 and lane_for(63,125) == 1
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
    assert parse_swap_used_mib('total = 2048,00M used = 1234,44M free = 813,56M (encrypted)') == 1234.44
    messages = []
    monitor = ContinuousMemoryMonitor(sample_fn=lambda: {
        'pressure': 4, 'available_pct': 4, 'swap_used_mib': 9000.0,
        'monotonic': 0.0}, clock=lambda: 0.0, output_fn=messages.append)
    assert monitor.check(999999, 16000.0)[0] == ''
    with LOCK:
        RUNNING_RSS_MIB.pop(999999, None)
    env = imapsync_environment({'LC_ALL':'de_DE.UTF-8', 'LANG':'en_US.UTF-8'})
    assert 'LC_ALL' not in env and env['LC_MESSAGES'] == 'C'
    assert env['LC_CTYPE'] == 'de_DE.UTF-8'
    parallel = ContinuousMemoryMonitor(workers=2, sample_fn=lambda: {
        'pressure': 1, 'available_pct': 75, 'swap_used_mib': 0}, output_fn=messages.append)
    assert parallel.RSS_WARNING_MIB == 7680
    assert parallel.COMBINED_WARNING_MIB == 10240
    assert parallel.check(999997, 5200.0)[0] == ''
    assert not parallel.serial_requested.is_set()
    assert parallel.check(999998, 5200.0)[0] == ''
    assert parallel.serial_requested.is_set()
    with LOCK:
        RUNNING_RSS_MIB.pop(999997, None)
        RUNNING_RSS_MIB.pop(999998, None)
    original = [1, 4, 8, 10, 12]
    sample_state = dict(snapshot_count=5, snapshot_max_uid=12,
                        source_uid_sha256=digest_uids(original))
    sample_rows = [(1, 8, 3), (10, 12, 2)]
    restored, gaps, fresh = verify_original_snapshot(sample_state, sample_rows,
                                                      original[:-1], allowed_missing=(12,))
    assert restored == original and gaps == (12,) and fresh == 0
    try:
        verify_original_snapshot(sample_state, sample_rows, [1, 8, 10],
                                 allowed_missing=(12,))
    except RuntimeError:
        pass
    else:
        raise AssertionError('Unbekannte zweite Quell-Luecke muss blockieren')
    progress_state = dict(completed=[0], available_processed=[1],
                          safe_chunk_totals={'1': {'selected': 1}}, safe_chunk_next={'1': 1})
    assert count_verified_progress(progress_state, sample_rows) == 4
    print('SELFTEST OK: UID-Batches, Worker-Grenzen, Log-Parser, Locale-Fix, RAM-Warnungen, weiche Parallelitaetsreduktion, Original-Hash-Recovery, offene Luecken.')



def packet_cache_lane(state, index, n_batches):
    plan = state.get('cache_lane_plan')
    if plan is None:
        return lane_for(index, n_batches)
    try:
        lane = plan['mapping'][str(index)]
    except (KeyError, TypeError) as exc:
        raise RuntimeError('Paket fehlt in der dauerhaften Cache-Zuordnung') from exc
    if type(lane) is not int or not 0 <= lane < 4:
        raise RuntimeError('Ungueltige dauerhafte Cache-Lane')
    return lane



def backup_state_before_v29():
    backup_dir = ROOT / 'backups'
    secure_dir(backup_dir)
    fd, backup = tempfile.mkstemp(prefix='migration-before-v29-', suffix='.json', dir=backup_dir)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(STATE.read_bytes())
        stream.flush()
        os.fsync(stream.fileno())
    return backup



def copied_log_metrics(log_text):
    """Only informative throughput evidence; never a checkpoint substitute."""
    copies = {}
    for match in re.finditer(r'^msg\s+INBOX/(\d+)\s+\{(\d+)\}.*\bcopied to\s+INBOX/',
                             log_text, flags=re.MULTILINE):
        copies[int(match.group(1))] = int(match.group(2))
    return len(copies), sum(copies.values())



def throttle_details(log_text):
    throttled = bool(re.search(
        r'Request is throttled|\bServerBusy\b|too many (?:simultaneous )?(?:connections|requests)'
        r'|maximum (?:number of )?(?:concurrent )?connections.*(?:reached|exceeded)',
        log_text, flags=re.IGNORECASE))
    waits = re.findall(r'(?:Suggested\s+)?Backoff\s+Time\s*:\s*(\d+)\s*milliseconds',
                       log_text, flags=re.IGNORECASE)
    delay = max((int(value) / 1000 for value in waits), default=0.0)
    return throttled, delay



def retry_wait(seconds, stop_event, label):
    """Automatic, interruptible server backoff with visible heartbeat."""
    deadline = time.monotonic() + seconds
    next_message = time.monotonic()
    while time.monotonic() < deadline:
        if stop_event is not None and stop_event.is_set():
            raise RuntimeError('Wiederholung durch Sofortstopp beendet')
        now = time.monotonic()
        if now >= next_message:
            print(f'[{time.strftime("%H:%M:%S")}] AUTOMATISCHER RETRY {label}: '
                  f'in etwa {max(1, int(deadline-now))} s; keine Eingabe erforderlich.', flush=True)
            next_message = now + HEARTBEAT_SECONDS
        delay = min(1.0, max(0.0, deadline - now))
        if stop_event is None:
            time.sleep(delay)
        else:
            stop_event.wait(delay)



def do_selftest():
    _legacy_selftest()
    rows = [(1 + 200*i, 200 + 200*i, 200) for i in range(8)]
    manifest = ''.join(f'{a}\t{b}\t{n}\n' for a, b, n in rows)
    sample = dict(schema=2, manifest_sha256=hashlib.sha256(manifest.encode()).hexdigest(),
                  source_uid_sha256=digest_uids(list(range(1, 1601))),
                  snapshot_count=1600, snapshot_max_uid=1600, completed=[0],
                  attempts={'0': 1}, results={}, in_progress={})
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        mapping, metadata = build_or_validate_lane_plan(sample, rows, root/'logs', root)
        assert mapping['0'] == 0 and set(mapping.values()) == {0, 1, 2, 3}
        sample.update(schema=3, cache_lane_plan=metadata)
        again, _ = build_or_validate_lane_plan(sample, rows, root/'logs', root)
        assert mapping == again
        corrupted = copy.deepcopy(sample)
        corrupted['cache_lane_plan']['mapping']['0'] = 2
        try:
            build_or_validate_lane_plan(corrupted, rows, root/'logs', root)
        except RuntimeError:
            pass
        else:
            raise AssertionError('Geaenderte Cache-Zuordnung muss blockieren')
    output = []
    controller = AdaptiveParallelism(max_workers=4, benchmark=False, output_fn=output.append)
    gate = ChunkConcurrencyGate(controller)
    for lane in range(4):
        assert gate.acquire(lane)
    assert len(gate.active) == 4
    controller.degrade('Offline-Selbsttest', limit=1)
    assert len(gate.active) == 4 and controller.limit == 1
    for lane in range(4):
        gate.release(lane, successful=True, transferred=1, copied_bytes=10)
    for lane in range(4):
        assert gate.acquire(lane)
        gate.release(lane, successful=True, transferred=0, copied_bytes=0)
    assert not gate.active
    assert copied_log_metrics('msg INBOX/12 {123} copied to INBOX/90\n'
                              'msg INBOX/12 {123} copied to INBOX/91\n') == (1, 123)
    assert throttle_details('BAD Request is throttled. Suggested Backoff Time: 1250 milliseconds') == (True, 1.25)
    print('SELFTEST V2.9 OK: vier Cache-Lanes, feste Besitzzuordnung, Schema-Schutz, '
          'Rueckfall ohne Transferabbruch, Kopiermessung, Server-Backoff. Keine Postfachzugriffe.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['selftest', 'doctor', 'recover', 'run-safe',
                                           'resume-smart', 'follow', 'memcheck', 'status', 'audit', 'oauth-refresh'])
    parser.add_argument('--workers', type=int, choices=(1, 2, 3, 4), default=4,
                        help='Maximale Parallelitaet der Fortsetzung (Standard: 4; produktive Stufenmessung)')
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
    if args.action == 'follow':
        follow_current_run(workers=args.workers)
        return
    with (ROOT / 'run.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Ein anderer Migrationslauf ist bereits aktiv; diesen nicht parallel starten') from exc
        password = getpass.getpass('Quellpostfach-Passwort: ')
        if args.action == 'doctor':
            do_doctor(password)
        elif args.action in ('recover', 'run-safe', 'resume-smart'):
            recover_parallel(password, workers=args.workers)
        elif args.action == 'audit':
            do_audit(password)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nUnterbrochen. Mit derselben Version und unveraendertem Cache fortfahren.', file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print('FEHLER:', e, file=sys.stderr)
        sys.exit(1)
