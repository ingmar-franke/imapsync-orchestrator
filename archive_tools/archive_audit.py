#!/usr/bin/env python3
"""Read-only, restartable IMAP migration audit.

Indexes source and destination headers in SQLite; verifies UIDVALIDITY and
source UID snapshots. Never modifies messages. Requires an orchestrator state
and a separately installed OAuth helper for the target mailbox."""
from __future__ import annotations
from archive_tools import config as cfg

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from email import policy
from email.parser import BytesHeaderParser
import fcntl
import getpass
import hashlib
import imaplib
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
import sys
import time
from typing import Callable

DEFAULT_ROOT = cfg.MIGRATION_ROOT
DEFAULT_OUT = cfg.AUDIT_ROOT
SOURCE_FOLDER = {"inbox": cfg.SOURCE_INBOX_FOLDER, "sent": cfg.SOURCE_SENT_FOLDER}
TARGET_FOLDER = {"inbox": cfg.TARGET_INBOX_FOLDER, "sent": cfg.TARGET_SENT_FOLDER}
SOURCE_HOST = cfg.SOURCE_HOST
TARGET_HOST = cfg.TARGET_HOST
TARGET_OAUTH = cfg.OAUTH_HELPER
TARGET_TOKEN = cfg.OAUTH_TOKEN
FETCH_BATCH = 100
FIELDS = "(MESSAGE-ID RECEIVED DATE FROM TO SUBJECT)"
imaplib._MAXLINE = 20_000_000


def fail(message: str) -> None:
    raise RuntimeError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_uids(uids) -> str:
    h = hashlib.sha256()
    for uid in uids:
        h.update(f"{uid}\n".encode("ascii"))
    return h.hexdigest()


def safe_private_dir(path: Path) -> None:
    if path.is_symlink():
        fail(f"Ausgabeverzeichnis ist ein Symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def write_private_json(path: Path, value: dict) -> None:
    # This is an audit-only output. No file under the migration work directory
    # is modified. Atomic update avoids partial reports on interruptions.
    data = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    import tempfile
    if path.is_symlink():
        fail('Refusing symlink output')
    fd, tmp_name = tempfile.mkstemp(prefix='.report-', dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def save_private_evidence_copy(out: Path, prefix: str, source: Path) -> str:
    """Snapshot a tiny state/manifest file without touching its source."""
    safe_private_dir(out)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    dest = out / f"{prefix}-{stamp}{source.suffix}"
    content = source.read_bytes()  # orchestrator replaces these files atomically
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
    return dest.name


def state_and_manifest(root: Path):
    state_path = root / "migration.json"
    manifest_path = root / "uid_pakete.tsv"
    if not (state_path.is_file() and manifest_path.is_file()):
        fail("migration.json oder uid_pakete.tsv fehlen. Nichts neu initialisieren!")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("schema") != 3:
        fail("Erwartet V2.11-Migrationszustand mit Schema 3. Keine Statusmigration durch Audit!")
    if not re.fullmatch(r"[0-9a-f]{64}", str(state.get("source_uid_sha256", ""))):
        fail("Originaler Quell-UID-Hash ist ungueltig")
    manifest_bytes = manifest_path.read_bytes()
    if sha256(manifest_bytes) != state.get("manifest_sha256"):
        fail("Manifest-Hash passt nicht zum gespeicherten Migrationszustand")
    rows = []
    prev = 0
    for line in manifest_bytes.decode("utf-8").splitlines():
        start, end, n = [int(x) for x in line.split("\t")]
        if start <= prev or end < start or not 1 <= n <= 2000 or end - start + 1 < n:
            fail("Ungueltige oder ueberlappende UID-Pakete")
        rows.append((start, end, n))
        prev = end
    if (not rows or sum(n for _, _, n in rows) != state.get("snapshot_count")
            or rows[-1][1] != state.get("snapshot_max_uid")):
        fail("Migrations-Snapshot und Paketmanifest widersprechen sich")
    return state, rows


def packet_progress(state: dict, rows: list) -> dict:
    n = len(rows)
    completed = set(state.get("completed", []))
    available = set(state.get("available_processed", []))
    if not all(type(x) is int and 0 <= x < n for x in completed | available):
        fail("Ungueltige Paketnummer im Status")
    if completed & available:
        fail("Paket gleichzeitig abgeschlossen und als Quellenluecke eingetragen")
    totals = state.get("safe_chunk_totals", {})
    nexts = state.get("safe_chunk_next", {})
    selected = 0
    errors = []
    for index, (_, _, planned) in enumerate(rows):
        key = str(index)
        if index in completed:
            part = planned
        elif key in totals:
            part = totals[key].get("selected", -1)
        else:
            chunks = nexts.get(key, 0)
            part = min(chunks * 200, planned) if type(chunks) is int and chunks >= 0 else -1
        if type(part) is not int or not 0 <= part <= planned:
            errors.append(f"Paket {index+1}: unplausibler Checkpoint")
        else:
            selected += part
        if index in available:
            t = totals.get(key, {})
            if (t.get("selected", 0) + t.get("unavailable_source", 0) != planned
                    or nexts.get(key) != (planned + 199) // 200
                    or len(t.get("unavailable_uids", [])) != t.get("unavailable_source", 0)):
                errors.append(f"Paket {index+1}: Quellenluecken-Checkpoint unplausibel")
    missing = list(state.get("missing_source", []))
    normalized = []
    for v in missing:
        if not str(v).isdigit():
            fail("Unbekanntes Quellenlueckenformat")
        normalized.append(int(v))
    if errors:
        fail("; ".join(errors[:5]))
    return {
        "planned": state["snapshot_count"], "packet_count": n,
        "completed_packets": len(completed), "available_processed_packets": len(available),
        "all_packets_processed": len(completed | available) == n,
        "checkpointed_present": selected,
        "unacknowledged_or_unavailable": state["snapshot_count"] - selected,
        "known_missing_source_uids": normalized,
    }


def find_uid_traces(root: Path, uid: int) -> dict:
    """Inventory candidate traces, not proof that message content was archived."""
    cache_hits = []
    for lane in range(1, 11):
        parent = root / f"cache-worker{lane}" / "imapsync_cache"
        if not parent.is_dir():
            continue
        for current, _, names in os.walk(parent, followlinks=False):
            for name in names:
                if re.fullmatch(rf"{uid}_[0-9]+", name):
                    cache_hits.append(str((Path(current) / name).relative_to(root)))
    log_hits = []
    logs_dir = root / "logs"
    if logs_dir.is_dir():
        for p in logs_dir.glob("*.log"):
            if p.is_file() and p.stat().st_size <= 20_000_000:
                # An IMAP UID range or status line is NOT a message identity.
                if re.search(rf"(?<!\d){uid}(?!\d)", p.read_text(encoding="utf-8", errors="replace")):
                    log_hits.append(str(p.relative_to(root)))
    diagnostics = []
    d = root / "diagnostics"
    if d.is_dir():
        for p in d.rglob("*.json"):
            if p.is_file() and p.stat().st_size <= 10_000_000:
                if str(uid) in p.read_text(encoding="utf-8", errors="replace"):
                    diagnostics.append(str(p.relative_to(root)))
    return {
        "uid": uid, "cache_mapping_filename_candidates": cache_hits[:100],
        "logs_mentioning_uid_not_proof": log_hits[:100],
        "diagnostic_records_mentioning_uid": diagnostics[:100],
        "classification": "UNRESOLVED_SOURCE_UID_NO_PROVEN_MESSAGE_ID",
        "warning": "Quelle entfernt; UID allein ist auf Microsoft 365 nicht suchbar. "
                   "Eine UID-Bereichsangabe oder Cache-Datei beweist keinen Mailinhalt.",
    }


def prepare(root: Path, out: Path) -> dict:
    state, rows = state_and_manifest(root)
    progress = packet_progress(state, rows)
    result = {
        "prepared_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "offline-no-mailbox-access",
        "source_uidvalidity": state.get("uidvalidity1"),
        "target_uidvalidity": state.get("uidvalidity2"),
        "original_uid_sha256": state.get("source_uid_sha256"),
        "manifest_sha256": state.get("manifest_sha256"),
        "initial_target_count": state.get("initial_target_count"),
        "progress": progress,
        "missing_uid_evidence": {str(uid): find_uid_traces(root, uid) for uid in progress["known_missing_source_uids"]},
        "scope": ["INBOX", "Sent"],
        "comment": "Zwischenstand; keine inhaltliche Bestaetigung auf dem Zielserver.",
    }
    safe_private_dir(out)
    # Preserve the current status and immutable UID manifest as small local evidence.
    # No live IMAP calls, no password/token files, no cache/log mutations.
    result["evidence_copies"] = {
        "state": save_private_evidence_copy(out, "migration-status", root / "migration.json"),
        "manifest": save_private_evidence_copy(out, "uid-packet-plan", root / "uid_pakete.tsv"),
    }
    write_private_json(out / "vorpruefung.json", result)
    print("OFFLINE-VORPRUEFUNG OK (keine Serververbindung)")
    print(f"Quittiert: {progress['checkpointed_present']:,} / {progress['planned']:,}")
    print(f"Abgearbeitete Pakete: {progress['completed_packets']} + {progress['available_processed_packets']} / {len(rows)}")
    print(f"Offene Quellen-UIDs: {progress['known_missing_source_uids'] or 'keine gemeldet'}")
    print(f"Quellenlücken: {len(result['missing_uid_evidence'])} UID(s) separat dokumentiert")
    print("Bericht:", out / "vorpruefung.json")
    return result


def _imap_ssl(host):
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        ctx = ssl.create_default_context()
    if not host:
        fail("IMAP_SOURCE_HOST / IMAP_TARGET_HOST nicht konfiguriert")
    return imaplib.IMAP4_SSL(host, 993, ssl_context=ctx, timeout=120)


def close_imap_quietly(conn, *, graceful: bool = False) -> None:
    """Close a dead IMAP connection without masking the original exception."""
    if conn is None:
        return
    if graceful:
        try:
            conn.logout()
            return
        except Exception:
            pass
    shutdown = getattr(conn, "shutdown", None)
    if callable(shutdown):
        try:
            shutdown()
        except Exception:
            pass


def source_login(user: str, password: str):
    conn = _imap_ssl(SOURCE_HOST)
    try:
        if conn.login(user, password)[0] != "OK":
            fail("Quellanmeldung fehlgeschlagen")
    except BaseException:
        close_imap_quietly(conn)
        raise
    return conn


def refresh_oauth():
    if not (TARGET_OAUTH.is_file() and TARGET_TOKEN.is_file()):
        fail("OAuth-Helfer oder Ziel-Token-Datei fehlt")
    result = subprocess.run([sys.executable, str(TARGET_OAUTH), "--refresh"],
                            capture_output=True, text=True, timeout=180)
    if result.returncode:
        fail("Microsoft-365-OAuth-Refresh fehlgeschlagen (keine Zugangsdaten ausgegeben)")
    return TARGET_TOKEN.read_text(encoding="utf-8").strip()


def target_login(user: str):
    token = refresh_oauth()
    conn = _imap_ssl(TARGET_HOST)
    try:
        if conn.authenticate("XOAUTH2", lambda _: f"user={user}\x01auth=Bearer {token}\x01\x01".encode())[0] != "OK":
            fail("target IMAP-Anmeldung fehlgeschlagen")
    except BaseException:
        close_imap_quietly(conn)
        raise
    return conn


def select_readonly(imap, folder: str) -> tuple[int, str]:
    typ, dat = imap.select(cfg.quote_imap_folder(folder), readonly=True)
    if typ != "OK" or not dat or not dat[0]:
        fail(f"IMAP-Ordner {folder} nicht lesbar (EXAMINE)")
    kind, vals = imap.response("UIDVALIDITY")
    if kind != "UIDVALIDITY" or not vals or not vals[0]:
        fail(f"UIDVALIDITY fuer {folder} fehlt")
    return int(dat[0]), vals[0].decode("ascii")


def search_uids(imap) -> list[int]:
    typ, data = imap.uid("SEARCH", None, "ALL")
    if typ != "OK" or not data:
        fail("UID SEARCH ALL fehlgeschlagen")
    ids = [int(x) for x in (data[0] or b"").split()]
    if ids != sorted(set(ids)):
        fail("UIDs nicht aufsteigend oder nicht eindeutig")
    return ids


# Try at most six reconnections per interrupted FETCH, with a small backoff.
# The server can close an idle IMAP session without any data loss.
RECONNECT_DELAYS = (3, 7, 15, 30, 60, 90)
TRANSIENT_IMAP_ERRORS = (imaplib.IMAP4.abort, OSError, EOFError)


class ResilientReadOnlySession:
    """Read-only session with snapshot-validated restart for UID FETCH.

    Start() issues only EXAMINE and UID SEARCH ALL, and records (UIDVALIDITY,
    full UID digest, count). A replacement connection must have exactly the
    same metadata or the audit stops rather than mixing two snapshots.
    """

    def __init__(self, opener: Callable[[], object], folder: str, side: str):
        self._opener = opener
        self.folder = folder
        self.side = side
        self._conn = None
        self._expected = None
        self.reconnections = 0

    def start(self) -> tuple[int, str, list[int]]:
        if self._conn is not None:
            raise RuntimeError("Audit-IMAP-Session bereits verbunden")
        conn = self._opener()
        try:
            count, validity = select_readonly(conn, self.folder)
            uids = search_uids(conn)
            if len(uids) != count:
                fail(f"{self.side}/{self.folder}: Postfach veraenderte sich waehrend UID SEARCH")
            identity = (count, validity, digest_uids(uids))
            if self._expected is None:
                self._expected = identity
            elif self._expected != identity:
                fail(f"{self.side}/{self.folder}: UID-Liste oder UIDVALIDITY nach Neuverbindung "
                     "geaendert. Audit gestoppt, SQLite-Index bleibt erhalten.")
        except BaseException:
            close_imap_quietly(conn)
            raise
        self._conn = conn
        return count, validity, uids

    def _abandon(self) -> None:
        conn, self._conn = self._conn, None
        close_imap_quietly(conn)

    def uid(self, verb: str, *args):
        if verb != "FETCH":
            fail("Audit-Session erlaubt nur UID FETCH; UID SEARCH erfolgt bei der Validierung")
        failures = 0
        while True:
            try:
                if self._conn is None:
                    self.start()
                return self._conn.uid(verb, *args)
            except TRANSIENT_IMAP_ERRORS as err:
                self._abandon()
                if failures >= len(RECONNECT_DELAYS):
                    raise RuntimeError(
                        f"{self.side}/{self.folder}: IMAP-Verbindung nach "
                        f"{failures} Wiederholungen weiter unterbrochen; "
                        "gespeicherte Header bleiben erhalten. Gleichen verify-Befehl wiederholen."
                    ) from err
                seconds = RECONNECT_DELAYS[failures]
                failures += 1
                self.reconnections += 1
                print(f"{self.side}/{self.folder}: IMAP-Verbindungsabbruch ({type(err).__name__}); "
                      f"neuer Verbindungsversuch {failures}/{len(RECONNECT_DELAYS)} "
                      f"in {seconds}s. Letzte FETCH-Gruppe wird nur lesend wiederholt.",
                      flush=True)
                time.sleep(seconds)

    def close(self) -> None:
        conn, self._conn = self._conn, None
        close_imap_quietly(conn, graceful=True)


def _canonical(value: str) -> str:
    return " ".join(str(value or "").split())


def headers_from_fetch(data) -> dict[int, dict]:
    """Strict UID FETCH parser; does not mistake sequence numbers for UIDs."""
    result = {}
    parser = BytesHeaderParser(policy=policy.default)
    for element in data or []:
        if not (isinstance(element, tuple) and len(element) == 2):
            continue
        attr, raw = element
        if not (isinstance(attr, bytes) and isinstance(raw, bytes)):
            continue
        uid_match = re.search(rb"\bUID\s+(\d+)\b", attr, flags=re.I)
        size_match = re.search(rb"\bRFC822\.SIZE\s+(\d+)\b", attr, flags=re.I)
        if not uid_match:
            fail("UID fehlt in FETCH-Antwort")
        uid = int(uid_match.group(1))
        if uid in result:
            fail(f"UID {uid} doppelt in FETCH-Antwort")
        msg = parser.parsebytes(raw)
        def header(key: str) -> str:
            try:
                return _canonical(str(msg.get(key, "")))
            except Exception:
                return ""
        mid = header("Message-ID").strip("<>").lower()
        meta = [header("Date"), header("From"), header("To"), header("Subject")]
        received = [_canonical(str(x)) for x in msg.get_all("Received", [])]
        result[uid] = dict(
            msg_id=mid,
            received_count=len(received),
            # Stable clues: this is header evidence, not a cryptographic content hash.
            signature=sha256((mid + "\n" + "\n".join(received)).encode()),
            meta_signature=sha256((mid + "\n" + "\n".join(meta)).encode()),
            no_id_signature=sha256("\n".join(meta + received).encode()),
            size_bytes=int(size_match.group(1)) if size_match else None,
        )
    return result


def open_db(db_path: Path):
    if db_path.is_symlink() or db_path.parent.is_symlink():
        fail('Refusing symlink SQLite output path')
    db = sqlite3.connect(db_path)
    os.chmod(db_path, 0o600)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS folders (
          side TEXT NOT NULL, folder TEXT NOT NULL, uidvalidity TEXT NOT NULL,
          uid_list_sha256 TEXT NOT NULL, n_uids INTEGER NOT NULL,
          PRIMARY KEY (side, folder));
        CREATE TABLE IF NOT EXISTS headers (
          side TEXT NOT NULL, folder TEXT NOT NULL, uid INTEGER NOT NULL,
          msg_id TEXT NOT NULL, signature TEXT NOT NULL, meta_signature TEXT NOT NULL,
          no_id_signature TEXT NOT NULL, received_count INTEGER NOT NULL,
          size_bytes INTEGER,
          PRIMARY KEY (side, folder, uid));
        CREATE INDEX IF NOT EXISTS idx_strong ON headers(side, folder, signature);
        CREATE INDEX IF NOT EXISTS idx_meta ON headers(side, folder, meta_signature);
        CREATE INDEX IF NOT EXISTS idx_mid ON headers(side, folder, msg_id);
        CREATE INDEX IF NOT EXISTS idx_noid ON headers(side, folder, no_id_signature);
    """)
    db.commit()
    return db


def index_folder(db, imap, side: str, folder: str, uids: list[int], uidvalidity: str,
                 max_batches: int | None) -> bool:
    hashvalue = digest_uids(uids)
    prev = db.execute("SELECT uidvalidity, uid_list_sha256, n_uids FROM folders WHERE side=? AND folder=?",
                      (side, folder)).fetchone()
    if prev and prev != (uidvalidity, hashvalue, len(uids)):
        fail(f"{side}/{folder}: UID-Liste oder UIDVALIDITY seit letztem Audit veraendert. "
             "Datenbank nicht wiederverwenden; separat archivieren/umbenennen und neu pruefen.")
    with db:
        db.execute("INSERT OR IGNORE INTO folders VALUES(?,?,?,?,?)",
                   (side, folder, uidvalidity, hashvalue, len(uids)))
    fetched_groups = 0
    total = len(uids)
    for start in range(0, total, FETCH_BATCH):
        batch = uids[start:start + FETCH_BATCH]
        placeholders = ",".join("?" for _ in batch)
        already = {uid for (uid,) in db.execute(
            f"SELECT uid FROM headers WHERE side=? AND folder=? AND uid IN ({placeholders})",
            (side, folder, *batch))}
        missing = [uid for uid in batch if uid not in already]
        if not missing:
            continue
        if max_batches is not None and fetched_groups >= max_batches:
            return False
        typ, data = imap.uid("FETCH", ",".join(map(str, missing)),
                             f"(UID RFC822.SIZE BODY.PEEK[HEADER.FIELDS {FIELDS}])")
        if typ != "OK":
            fail(f"IMAP FETCH Fehler bei {side}/{folder}, UID {missing[0]}")
        entries = headers_from_fetch(data)
        if set(entries) != set(missing):
            fail(f"Unvollstaendige FETCH-Antwort {side}/{folder}: "
                 f"{len(entries)}/{len(missing)}. Kein fehlerhafter Checkpoint.")
        with db:
            db.executemany("INSERT INTO headers VALUES(?,?,?,?,?,?,?,?,?)", [
                (side, folder, uid, d["msg_id"], d["signature"], d["meta_signature"],
                 d["no_id_signature"], d["received_count"], d["size_bytes"])
                for uid, d in entries.items()])
        fetched_groups += 1
        if fetched_groups % 25 == 0 or start + FETCH_BATCH >= total:
            print(f"{side}/{folder}: bis {min(start + FETCH_BATCH, total):,} von {total:,} UIDs erfasst", flush=True)
    return db.execute("SELECT COUNT(*) FROM headers WHERE side=? AND folder=?",
                      (side, folder)).fetchone()[0] == total


def is_index_complete(db, side: str, folder: str) -> bool:
    meta = db.execute("SELECT n_uids FROM folders WHERE side=? AND folder=?", (side, folder)).fetchone()
    if not meta:
        return False
    count = db.execute("SELECT COUNT(*) FROM headers WHERE side=? AND folder=?", (side, folder)).fetchone()[0]
    return count == meta[0]


def compare_headers(db, folder: str, output_dir: Path) -> dict:
    kind = 'inbox' if folder == SOURCE_FOLDER['inbox'] else 'sent'
    target_folder = TARGET_FOLDER[kind]
    if not is_index_complete(db, "source", folder) or not is_index_complete(db, "target", target_folder):
        fail("Quell- und Zielindex muessen vollstaendig sein; sonst keine Vergleiche")
    # Repeated Message-IDs cannot establish a 1:1 match. We classify them
    # conservatively and report count discrepancies, never silently deduplicate.
    memo = {}
    def count(side: str, field: str, val: str) -> int:
        key = (side, field, val)
        if key not in memo:
            if field not in ("signature", "meta_signature", "msg_id", "no_id_signature"):
                fail("Unbekanntes Indexfeld")
            memo[key] = db.execute(
                f"SELECT COUNT(*) FROM headers WHERE side=? AND folder=? AND {field}=?",
                (side, folder if side == 'source' else target_folder, val)).fetchone()[0]
        return memo[key]
    classifications = Counter()
    examples = []
    for uid, mid, sig, meta, noid, received in db.execute(
            "SELECT uid,msg_id,signature,meta_signature,no_id_signature,received_count "
            "FROM headers WHERE side='source' AND folder=? ORDER BY uid", (folder,)):
        if not mid:
            kind = "NO_MESSAGE_ID_WEAK_METADATA_ONLY" if count("target", "no_id_signature", noid) else "NO_MESSAGE_ID_UNMATCHED"
        else:
            src_strong = count("source", "signature", sig)
            dst_strong = count("target", "signature", sig)
            if received and dst_strong >= src_strong:
                kind = "MATCH_ID_AND_RECEIVED_HEADERS"
            elif dst_strong and dst_strong < src_strong:
                kind = "SAME_ID_RECEIVED_BUT_MULTIPLICITY_DIFFERS"
            elif count("target", "meta_signature", meta) >= count("source", "meta_signature", meta):
                kind = "MATCH_ID_AND_BASIC_HEADERS"
            elif count("target", "msg_id", mid):
                kind = "MESSAGE_ID_ONLY_OR_DUPLICATE_COLLAPSE"
            else:
                kind = "MESSAGE_ID_NOT_IN_TARGET"
        classifications[kind] += 1
        if kind != "MATCH_ID_AND_RECEIVED_HEADERS" and len(examples) < 200:
            examples.append({"source_uid": uid, "class": kind, "message_id": mid})
    summary = {
        "folder": folder,
        "target_folder": target_folder,
        "source_headers": db.execute("SELECT n_uids FROM folders WHERE side='source' AND folder=?", (folder,)).fetchone()[0],
        "target_headers": db.execute("SELECT n_uids FROM folders WHERE side='target' AND folder=?", (target_folder,)).fetchone()[0],
        "classifications": dict(sorted(classifications.items())),
        "no_payload_or_attachment_comparison": True,
        "interpretation": "Header-ID-Abgleich ist Indiz, kein Bit-fuer-Bit-Nachweis. "
                          "Doppelte IDs und fehlende IDs koennen nicht sicher paarweise zugeordnet werden.",
        "source_missing_uid_check": "NOT_COVERED_BY_HEADER_MATCHING",
    }
    short = kind
    write_private_json(output_dir / f"abgleich_{short}.json", summary)
    write_private_json(output_dir / f"prueffaelle_{short}.json", {"max_sample": 200, "rows": examples})
    return summary


@contextmanager
def completed_migration_lock(root: Path, progress: dict):
    if not progress["all_packets_processed"]:
        fail("INBOX-Migration noch nicht abgearbeitet. Finale Onlinepruefung erst danach!")
    lockfile = root / "run.lock"
    if not lockfile.is_file():
        fail("run.lock fehlt; laufenden Prozess nicht sicher ausschliessbar")
    # open existing only, do not truncate or modify contents.
    with lockfile.open("a+") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("V2.11 laeuft noch! Onlinepruefung nicht parallel ausfuehren.")
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def verify(root: Path, out: Path, folder_key: str, max_batches: int | None):
    state, rows = state_and_manifest(root)
    progress = packet_progress(state, rows)
    safe_private_dir(out)
    with completed_migration_lock(root, progress):
        if progress["known_missing_source_uids"]:
            print("Quellenlücken werden getrennt vom Headerindex behandelt:", progress["known_missing_source_uids"])
        folder = SOURCE_FOLDER[folder_key]
        src_user, dst_user = state.get("user1"), state.get("user2")
        if not src_user or not dst_user:
            fail("Kontoangaben im Migrationsstatus fehlen")
        password = getpass.getpass("Quell-IMAP-Passwort: ")
        db = open_db(out / "header_index.sqlite3")
        try:
            # Crucial: DO NOT open target IMAP now. It will time out while hundreds
            # of thousands of headers are indexed on the Quelle server.
            src = ResilientReadOnlySession(
                lambda: source_login(src_user, password), SOURCE_FOLDER[folder_key], "source")
            try:
                src_count, src_validity, src_uids = src.start()
                if folder_key == "inbox":
                    if src_validity != state.get("uidvalidity1"):
                        fail("Quell-UIDVALIDITY weicht vom originalen INBOX-Snapshot ab")
                    original = [uid for uid in src_uids if uid <= state["snapshot_max_uid"]]
                    gaps = progress["known_missing_source_uids"]
                    if any(uid in original for uid in gaps):
                        fail("Bisher verschwundene UID ist wieder vorhanden: Quellbestand neu bewerten")
                    rebuilt = sorted(original + gaps)
                    if (len(rebuilt) != state["snapshot_count"]
                            or digest_uids(rebuilt) != state.get("source_uid_sha256")):
                        fail("Originaler UID-Snapshot kann nicht exakt rekonstruiert werden")
                    if len(original) != progress["checkpointed_present"]:
                        fail("Anzahl vorhandener Quell-UIDs passt nicht zu quittierten Checkpoints")
                    src_uids = original
                    print(f"UID-Snapshot kryptografisch rekonstruierbar; offene Luecke: {gaps}")
                print(f"Quelle {folder}: {len(src_uids):,} UIDs. "
                      "target IMAP-Verbindung wird erst nach Quellindex aufgebaut.", flush=True)
                existing_source = db.execute(
                    "SELECT COUNT(*) FROM headers WHERE side='source' AND folder=?", (folder,)
                ).fetchone()[0]
                print(f"Quell-Header bereits gespeichert: {existing_source:,} "
                      "(werden nicht erneut geladen).", flush=True)
                done_src = index_folder(db, src, "source", folder, src_uids, src_validity, max_batches)
                if not done_src:
                    print("Teilindex Quelle gespeichert. Gleichen verify-Befehl erneut ausfuehren; "
                          "Ziel noch nicht geprueft.")
                    return
            finally:
                src.close()
                password = None

            # A fresh target IMAP session, with independent retries and no idle wait
            # while the source is being indexed.
            dst = ResilientReadOnlySession(
                lambda: target_login(dst_user), TARGET_FOLDER[folder_key], "target")
            try:
                dst_count, dst_validity, dst_uids = dst.start()
                if folder_key == "inbox" and dst_validity != state.get("uidvalidity2"):
                    fail("Ziel-UIDVALIDITY weicht vom originalen INBOX-Snapshot ab")
                print(f"Nur lesend: {folder}: Quelle {len(src_uids):,}, "
                      f"Ziel {len(dst_uids):,} Eintraege.", flush=True)
                existing_target = db.execute(
                    "SELECT COUNT(*) FROM headers WHERE side='target' AND folder=?", (TARGET_FOLDER[folder_key],)
                ).fetchone()[0]
                print(f"Ziel-Header bereits gespeichert: {existing_target:,} "
                      "(werden nicht erneut geladen).", flush=True)
                done_dst = index_folder(db, dst, "target", TARGET_FOLDER[folder_key], dst_uids, dst_validity, max_batches)
                if not done_dst:
                    print("Teilindex gespeichert. Gleichen verify-Befehl erneut ausfuehren; "
                          "keine fertige Bewertung.")
                    return
            finally:
                dst.close()

            summary = compare_headers(db, folder, out)
            print("HEADER-ABGLEICH ERSTELLT:")
            for key, value in summary["classifications"].items():
                print(f"  {key}: {value:,}")
            print("Bericht:", out / f"abgleich_{folder_key}.json")
            if folder_key == "inbox" and progress["known_missing_source_uids"]:
                print("Historische Quellenlücken sind nicht Teil dieses Headernachweises:", progress["known_missing_source_uids"])
        finally:
            db.close()


def index_status(out: Path) -> None:
    """Show saved header progress without any IMAP access or SQLite writes."""
    path = out / "header_index.sqlite3"
    if not path.is_file():
        fail(f"Noch keine Headerdatenbank vorhanden: {path}")
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        rows = db.execute("""
            SELECT f.side, f.folder, f.n_uids, COUNT(h.uid)
            FROM folders f
            LEFT JOIN headers h ON h.side=f.side AND h.folder=f.folder
            GROUP BY f.side, f.folder, f.n_uids
            ORDER BY f.folder, f.side
        """).fetchall()
        if not rows:
            print("Header-Index ist leer.")
        for side, folder, expected, saved in rows:
            print(f"{side}/{folder}: {saved:,} von {expected:,} Headern gespeichert "
                  f"({saved / expected * 100 if expected else 100:.2f} %)")
        print("Nur lokaler Index gelesen; keine IMAP-Verbindung. Datei:", path)
    finally:
        db.close()


def report(out: Path):
    for name in ("vorpruefung.json", "abgleich_inbox.json", "abgleich_sent.json"):
        p = out / name
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            print(f"{name}: {data.get('prepared_utc', 'vorhanden')}; "
                  f"Klassifikationen: {data.get('classifications', 'noch keine')}")
        else:
            print(f"{name}: noch nicht erstellt")
    print("Bei einem Eintrag 'UNRESOLVED' oder nicht nachgewiesenen Message-IDs "
          "keinen vollstaendigen Archivierungsnachweis behaupten.")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", choices=("prepare", "verify", "report", "index-status"))
    p.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--folder", choices=("inbox", "sent"), default="inbox")
    p.add_argument("--max-batches", type=int, default=None,
                   help="Optional begrenzte neue 100er-FETCH-Gruppen je Postfach und Aufruf")
    args = p.parse_args(argv)
    if args.max_batches is not None and args.max_batches < 1:
        p.error("--max-batches muss >= 1 sein")
    os.umask(0o077)
    if args.action == "prepare":
        prepare(args.root, args.out)
    elif args.action == "verify":
        verify(args.root, args.out, args.folder, args.max_batches)
    elif args.action == "index-status":
        index_status(args.out)
    else:
        report(args.out)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Audit angehalten; vorhandene Datenbank bleibt fuer Wiederaufnahme erhalten.", file=sys.stderr)
        sys.exit(130)
    except (RuntimeError, ValueError, sqlite3.Error, OSError, json.JSONDecodeError) as exc:
        print("AUDIT FEHLER:", exc, file=sys.stderr)
        sys.exit(1)
