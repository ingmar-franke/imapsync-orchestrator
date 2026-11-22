#!/usr/bin/env python3
"""Read-only MIME integrity and multiplicity validator.

Compares source/target IMAP message bytes and decoded MIME leaf payloads with
SHA-256 and stores only derived fingerprints and private local reports."""
from __future__ import annotations
from archive_tools import config as cfg

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

FOLDER = cfg.SOURCE_SENT_FOLDER
TARGET_FOLDER = cfg.TARGET_SENT_FOLDER
DEFAULT_OUT = cfg.AUDIT_ROOT
DEFAULT_ROOT = cfg.MIGRATION_ROOT
PROGRESS_NAME = "sent_mime_progress.json"
REPORT_NAME = "sent_mime_report.json"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def stable_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def private_write(path: Path, data: dict) -> None:
    """Atomic, private, no symlink as destination."""
    if path.is_symlink():
        raise RuntimeError(f"Symlink nicht zulässig: {path}")
    if path.parent.is_symlink():
        raise RuntimeError(f"Symlink-Verzeichnis nicht zulässig: {path.parent}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temp = path.with_name(path.name + ".tmp")
    if temp.is_symlink():
        raise RuntimeError(f"Symlink nicht zulässig: {temp}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def load_json(path: Path):
    if not path.exists():
        return None
    if path.is_symlink():
        raise RuntimeError(f"Symlink nicht zulässig: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_plan(db_path: Path) -> dict:
    """Read only, require both complete indexes and find source excess groups."""
    if not db_path.is_file() or db_path.is_symlink():
        raise RuntimeError(f"Header-Datenbank nicht gefunden bzw. Symlink: {db_path}")
    conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        folders = {}
        rows = {}
        for side in ("source", "target"):
            meta = conn.execute(
                "SELECT uidvalidity, uid_list_sha256, n_uids FROM folders WHERE side=? AND folder=?",
                (side, FOLDER if side == 'source' else TARGET_FOLDER),
            ).fetchone()
            if not meta:
                raise RuntimeError(f"Fehlender Index: {side}/{FOLDER}")
            uidvalidity, uid_hash, count = meta
            records = conn.execute(
                "SELECT uid, signature, msg_id, meta_signature, size_bytes FROM headers "
                "WHERE side=? AND folder=? ORDER BY uid", (side, FOLDER if side == 'source' else TARGET_FOLDER),
            ).fetchall()
            if count != len(records):
                raise RuntimeError(f"Unvollständiger Index: {side}/{FOLDER}: {len(records)}/{count}")
            h = hashlib.sha256()
            for row in records:
                h.update(f"{row[0]}\n".encode("ascii"))
            if h.hexdigest() != uid_hash:
                raise RuntimeError(f"UID-Hash im lokalen Index passt nicht: {side}/{FOLDER}")
            folders[side] = {"uidvalidity": uidvalidity, "uid_list_sha256": uid_hash, "n_uids": count}
            rows[side] = records
    finally:
        conn.close()

    byside = {}
    for side in ("source", "target"):
        d = defaultdict(list)
        for uid, signature, mid, meta, size in rows[side]:
            d[signature].append({"uid": int(uid), "size": size, "has_mid": bool(mid), "meta": meta})
        byside[side] = d
    cases = []
    for key in sorted(set(byside["source"]) | set(byside["target"])):
        src = byside["source"].get(key, [])
        dst = byside["target"].get(key, [])
        if len(src) <= len(dst):
            continue
        cases.append({
            "group": len(cases) + 1,
            "signature_sha256": key,
            "source": src,
            "target": dst,
            "source_excess": len(src) - len(dst),
        })
    plan = {
        "schema": 1,
        "folder": FOLDER,
        "index_sides": folders,
        "cases": cases,
        "source_total": len(rows["source"]),
        "target_total": len(rows["target"]),
    }
    plan["plan_digest"] = sha(stable_json(plan))
    return plan


def plan_summary(plan: dict) -> None:
    cases = plan["cases"]
    src_uids = sum(len(x["source"]) for x in cases)
    dst_uids = sum(len(x["target"]) for x in cases)
    print("OFFLINE-PLAN (nur SQLite gelesen; keine Serververbindung)")
    print(f"Quelle: {plan['source_total']:,} | target IMAP: {plan['target_total']:,}")
    print(f"Quell-Überhang: {sum(x['source_excess'] for x in cases)} in {len(cases)} Gruppen")
    print(f"Gezielt zu prüfende Einträge: {src_uids} Quelle + {dst_uids} Ziel = {src_uids + dst_uids}")
    large = [(side, row['uid'], row['size']) for case in cases for side in ("source", "target")
             for row in case[side] if row["size"] is None]
    if large:
        print(f"Hinweis: {len(large)} Einträge ohne RFC822.SIZE; werden im Online-Modus nicht ungesehen geladen.")
    known_sizes = [row["size"] for case in cases for side in ("source", "target")
                   for row in case[side] if row["size"] is not None]
    if known_sizes:
        print(f"Gesamtes bekanntes Abrufvolumen: {sum(known_sizes) / (1024**2):,.1f} MiB; "
              f"größte Nachricht: {max(known_sizes) / (1024**2):,.1f} MiB")
        print(f"Über Standardlimit 30 MiB: {sum(x > 30 * 1024**2 for x in known_sizes)} Nachrichten")
    print("Vollständigkeit bisher nur auf Headerbasis; kein inhaltlicher Nachweis.")


def strict_fetch_one(session, uid: int, expected_size: int | None):
    """Read only a *complete* BODY[] literal, not a partial FETCH response.

    RFC822.SIZE describes the RFC822 message size, while the literal marker
    describes how many octets this specific FETCH response actually sends.
    Some servers return different values. The literal length is the network
    integrity check; discrepancies with RFC822.SIZE are still diagnostic.
    """
    typ, data = session.uid("FETCH", str(uid), "(UID RFC822.SIZE BODY.PEEK[])")
    if typ != "OK":
        raise RuntimeError(f"UID FETCH nicht OK: {uid}")
    found = []
    for item in data or []:
        if not (isinstance(item, tuple) and len(item) == 2):
            continue
        attr, body = item
        if not isinstance(attr, bytes) or not isinstance(body, bytes):
            continue
        uid_m = re.search(rb"\bUID\s+(\d+)\b", attr, re.I)
        size_m = re.search(rb"\bRFC822\.SIZE\s+(\d+)\b", attr, re.I)
        # Require BODY[] (full message) and not BODY[]<0> (partial response).
        # imaplib returns each IMAP literal as a (response-prefix, bytes) tuple.
        literal_m = re.search(rb"\bBODY\[\]\s+\{(\d+)\+?\}\s*$", attr, re.I)
        if not uid_m or not size_m:
            raise RuntimeError("IMAP FETCH Antwort enthält keine UID oder SIZE")
        if not literal_m:
            raise RuntimeError(f"UID {uid}: kein vollständiges BODY[]-Literal in IMAP-Antwort")
        received_uid = int(uid_m.group(1))
        received_size = int(size_m.group(1))
        literal_size = int(literal_m.group(1))
        if received_uid != uid:
            raise RuntimeError(f"Unerwartete UID statt {uid}: {received_uid}")
        if literal_size != len(body):
            raise RuntimeError(f"UID {uid}: IMAP-Literal {literal_size} != Nutzdaten {len(body)}")
        if expected_size is not None and expected_size != received_size:
            raise RuntimeError(f"UID {uid}: RFC822.SIZE gegenüber Headerindex verändert "
                               f"({expected_size} -> {received_size})")
        found.append((received_size, body, received_size != literal_size))
    if len(found) != 1:
        raise RuntimeError(f"UID {uid}: {len(found)} statt genau einem FETCH-Datensatz")
    return found[0]


def verified_fetch_one(session, uid: int, expected_size: int | None):
    """Repeat inconsistent FETCH; never silently treat it as a clean proof."""
    size, body, mismatch = strict_fetch_one(session, uid, expected_size)
    if mismatch:
        # A complete IMAP literal is not necessarily a complete RFC822 message;
        # reject obvious malformed responses and require a stable second fetch.
        if not re.search(rb"\r?\n\r?\n", body):
            raise RuntimeError(f"UID {uid}: BODY[] mit Größenabweichung enthält keine Header/Body-Grenze")
        size2, body2, mismatch2 = strict_fetch_one(session, uid, expected_size)
        if size2 != size or mismatch2 != mismatch or body2 != body:
            raise RuntimeError(f"UID {uid}: BODY[] mit Größenabweichung bei Wiederholung instabil; "
                               "kein Inhaltsnachweis")
        del body2
        print(f"WARNUNG UID {uid}: RFC822.SIZE={size}, vollständiges IMAP-Literal={len(body)}; "
              "zweiter FETCH identisch. Größenabweichung wird im Bericht separat ausgewiesen.",
              flush=True)
    return size, body, mismatch


def mime_evidence(raw: bytes) -> dict:
    """Hash message and decoded MIME leaf payloads, without saving user data."""
    message = BytesParser(policy=policy.default).parsebytes(raw)
    parts = []
    fallback_parts = 0
    for part in message.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            # Keep fallback differentiated from a decoded payload.
            value = part.get_payload()
            if isinstance(value, str):
                payload = value.encode("utf-8", errors="surrogateescape")
            elif isinstance(value, bytes):
                payload = value
            else:
                payload = b""
            decode_mode = "fallback"
            fallback_parts += 1
        else:
            decode_mode = "decoded"
        parts.append({
            "type": part.get_content_type(),
            "disposition": part.get_content_disposition() or "",
            "filename": part.get_filename() or "",
            "decode_mode": decode_mode,
            "part_size": len(payload),
            "part_sha256": sha(payload),
        })
    return {"raw_sha256": sha(raw), "mime_sha256": sha(stable_json(parts)), "mime_parts": len(parts),
            "mime_fallback_parts": fallback_parts}


def initial_progress(plan: dict) -> dict:
    return {"schema": 1, "plan_digest": plan["plan_digest"], "folder": FOLDER,
            "results": {"source": {}, "target": {}}, "errors": []}


def verify_progress_shape(plan: dict, progress: dict) -> None:
    if not isinstance(progress, dict) or progress.get("schema") != 1 or progress.get("plan_digest") != plan["plan_digest"]:
        raise RuntimeError("Gespeicherter Fortschritt gehört nicht zum aktuellen Headerindex/Plan")
    for side in ("source", "target"):
        seen = {str(r["uid"]) for case in plan["cases"] for r in case[side]}
        actual = progress.get("results", {}).get(side, {})
        if not isinstance(actual, dict) or any(uid not in seen for uid in actual):
            raise RuntimeError(f"Ungültige Fortschrittsdaten: {side}")


def save_progress(out: Path, value: dict) -> None:
    value["saved_utc"] = datetime.now(timezone.utc).isoformat()
    private_write(out / PROGRESS_NAME, value)


def run_online(plan: dict, out: Path, root: Path, max_size_mib: int, max_messages: int | None) -> None:
    # Import from the previously verified audit script, which owns all
    # connection credentials and reconnect-with-UID-snapshot-validation logic.
    from archive_tools.archive_audit import (
        ResilientReadOnlySession, source_login, target_login, state_and_manifest,
        packet_progress, completed_migration_lock, digest_uids,
    )
    state, rows = state_and_manifest(root)
    progress_state = packet_progress(state, rows)
    if not progress_state["all_packets_processed"]:
        raise RuntimeError("Posteingangsmigration nicht abgeschlossen")
    src_user, dst_user = state.get("user1"), state.get("user2")
    if not src_user or not dst_user:
        raise RuntimeError("Kontoinformationen im bestehenden Migrationsstatus fehlen")
    cap = max_size_mib * 1024 * 1024
    progress_path = out / PROGRESS_NAME
    progress = load_json(progress_path) or initial_progress(plan)
    verify_progress_shape(plan, progress)
    attempted = 0
    with completed_migration_lock(root, progress_state):
        # Connect separately, never keep the target connection idle during Quelle work.
        for side in ("source", "target"):
            pending = [row for case in plan["cases"] for row in case[side]
                       if str(row["uid"]) not in progress["results"][side]
                       or (progress["results"][side][str(row["uid"])].get("status") == "skipped_size"
                           and row["size"] is not None and row["size"] <= cap)]
            if not pending:
                print(f"{side}: keine offenen Einträge")
                continue
            if side == "source":
                password = getpass.getpass("Quell-IMAP-Passwort: ")
                opener = lambda: source_login(src_user, password)
            else:
                opener = lambda: target_login(dst_user)
            session = ResilientReadOnlySession(opener, FOLDER if side == 'source' else TARGET_FOLDER, side)
            try:
                current_count, uidvalidity, uids = session.start()
                db_meta = plan["index_sides"][side]
                if (current_count != db_meta["n_uids"]
                    or uidvalidity != db_meta["uidvalidity"]
                    or digest_uids(uids) != db_meta["uid_list_sha256"]):
                    raise RuntimeError(f"{side}: Postfachstand/UIDVALIDITY gegenüber Headerindex verändert; Abbruch")
                print(f"{side}/{FOLDER}: unveränderter UID-Snapshot bestätigt ({current_count:,})")
                for row in pending:
                    uid, size = int(row["uid"]), row["size"]
                    if max_messages is not None and attempted >= max_messages:
                        print(f"Testlimit {max_messages} erreicht; Zwischenstand gespeichert")
                        return
                    if size is None or size > cap:
                        progress["results"][side][str(uid)] = {
                            "status": "skipped_size", "size": size,
                            "reason": "unknown_size" if size is None else "over_size_limit",
                        }
                        save_progress(out, progress)
                    else:
                        received_size, raw, size_mismatch = verified_fetch_one(session, uid, size)
                        fetched_octets = len(raw)
                        evidence = mime_evidence(raw)
                        del raw
                        progress["results"][side][str(uid)] = {
                            "status": "ok", "size": received_size,
                            "fetched_octets": fetched_octets,
                            "size_mismatch": size_mismatch, **evidence,
                        }
                        save_progress(out, progress)
                    attempted += 1
                    if attempted % 10 == 0:
                        done = len(progress["results"][side])
                        print(f"{side}: {done} Einträge bearbeitet", flush=True)
            finally:
                session.close()
                if side == "source":
                    password = None
    print("Online-Abgleich abgeschlossen oder Größenlimit erreicht. Bericht lokal mit 'report' erzeugen.")


def summary_report(plan: dict, progress: dict) -> dict:
    verify_progress_shape(plan, progress)
    cases = []
    summary = Counter()
    for case in plan["cases"]:
        src = [progress["results"]["source"].get(str(row["uid"])) for row in case["source"]]
        dst = [progress["results"]["target"].get(str(row["uid"])) for row in case["target"]]
        if any(x is None or x.get("status") != "ok" for x in src + dst):
            category = "UNRESOLVED_NOT_ALL_CONTENT_FETCHED"
            diff_variants = None
            raw_paired = None
        elif any(x.get("mime_fallback_parts", 0) for x in src + dst):
            category = "UNRESOLVED_MIME_DECODING_FALLBACK"
            diff_variants = None
            raw_paired = None
        else:
            src_mime, dst_mime = Counter(x["mime_sha256"] for x in src), Counter(x["mime_sha256"] for x in dst)
            src_raw, dst_raw = Counter(x["raw_sha256"] for x in src), Counter(x["raw_sha256"] for x in dst)
            extra_mime = sum(1 for k in src_mime if k not in dst_mime)
            raw_paired = sum(min(src_raw[k], dst_raw[k]) for k in src_raw.keys() | dst_raw.keys())
            diff_variants = extra_mime
            if extra_mime:
                category = "SOURCE_CONTENT_VARIANTS_ABSENT_IN_HEADER_GROUP"
            elif any(k not in src_mime for k in dst_mime):
                category = "SOURCE_TARGET_CONTENT_VARIANTS_DIFFER"
            elif set(src_mime) == set(dst_mime):
                if set(src_raw) == set(dst_raw):
                    category = "EXTRA_SOURCE_COPIES_OF_PRESENT_RAW_CONTENT"
                else:
                    category = "EXTRA_SOURCE_COPIES_OF_PRESENT_MIME_CONTENT"
            else:
                category = "UNRESOLVED_CONTENT_RELATION"
        summary[category] += 1
        cases.append({
            "group": case["group"],
            "source_uids": [r["uid"] for r in case["source"]],
            "target_uids": [r["uid"] for r in case["target"]],
            "source_count": len(case["source"]),
            "target_count": len(case["target"]),
            "extra_source_entries": case["source_excess"],
            "status": category,
            "source_only_mime_variants": diff_variants,
            "exact_raw_pairs": raw_paired,
            "source_sizes": [r["size"] for r in case["source"]],
            "target_sizes": [r["size"] for r in case["target"]],
            "source_size_discrepancies": [r["uid"] for r, x in zip(case["source"], src)
                                          if x and x.get("size_mismatch")],
            "target_size_discrepancies": [r["uid"] for r, x in zip(case["target"], dst)
                                          if x and x.get("size_mismatch")],
            "comparison_basis": ("raw_imap_bytes" if category == "EXTRA_SOURCE_COPIES_OF_PRESENT_RAW_CONTENT"
                                 else "decoded_mime_parts" if category == "EXTRA_SOURCE_COPIES_OF_PRESENT_MIME_CONTENT"
                                 else "unresolved_or_content_difference"),
        })
    return {
        "schema": 1,
        "folder": FOLDER,
        "plan_digest": plan["plan_digest"],
        "summary": dict(sorted(summary.items())),
        "source_excess_total": sum(x["source_excess"] for x in plan["cases"]),
        "size_discrepancies": {
            side: sum(bool(x.get("size_mismatch")) for x in progress["results"][side].values())
            for side in ("source", "target")
        },
        "groups_with_size_discrepancies": sum(
            bool(g["source_size_discrepancies"] or g["target_size_discrepancies"])
            for g in cases
        ),
        "groups": cases,
        "warning": "RFC822.SIZE und BODY[] können bei den Servern abweichen. Der FETCH-Inhalt wird nur bei vollständigem, bei Abweichung zweimal identischem IMAP-Literal gehasht. Gleichheit belegt nur dieselben aktuell per IMAP sichtbaren Bytes beziehungsweise dieselben dekodierten MIME-Teile; sie beweist weder identische ursprüngliche RFC822-Daten noch eine Übertragung der zusätzlichen Quellexemplare. Bei Abweichungen bleibt eine separate Qualitätswarnung bestehen. Eine nicht gefundene Inhaltsvariante fehlt nur innerhalb der passenden Headergruppe, nicht nachweislich im gesamten Zielpostfach. Keine Mail wird verändert, übertragen oder gelöscht.",
    }


def run_report(plan: dict, out: Path):
    progress = load_json(out / PROGRESS_NAME) or initial_progress(plan)
    report = summary_report(plan, progress)
    private_write(out / REPORT_NAME, report)
    print("OFFLINE-MIME-REPORT (keine Serververbindung)")
    for status, n in report["summary"].items():
        print(f"  {status}: {n} Gruppen")
    counts = report["size_discrepancies"]
    print(f"  RFC822.SIZE/BODY[]-Abweichungen: Quelle {counts['source']}, Ziel {counts['target']}; "
          f"betroffene Gruppen {report['groups_with_size_discrepancies']}")
    print(f"  Netto-Mehrfachexemplare in Quelle: {report['source_excess_total']}")
    print("  Achtung: Vergleich gilt für aktuell per IMAP gelieferte Inhalte, nicht für ursprüngliche Rohdaten.")
    print(f"Bericht: {out / REPORT_NAME}")
    print("Historische Quellenlücken sind separat zu behandeln.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["plan", "verify", "report"])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--max-size-mib", type=int, default=30)
    parser.add_argument("--max-messages", type=int, default=None,
                        help="Testweise höchstens so viele UID-Inhalte abrufen; danach fortsetzen")
    args = parser.parse_args()
    if args.max_size_mib <= 0 or args.max_size_mib > 200:
        parser.error("--max-size-mib muss zwischen 1 und 200 liegen")
    if args.max_messages is not None and args.max_messages < 1:
        parser.error("--max-messages muss mindestens 1 sein")
    args.out = args.out.expanduser()
    if args.out.is_symlink():
        parser.error("Audit-Verzeichnis darf kein Symlink sein")
    plan = load_plan(args.out / "header_index.sqlite3")
    if args.action == "plan":
        plan_summary(plan)
        print(f"Planprüfsumme: {plan['plan_digest']}")
        print("Keine Nachrichten geladen. Zum Inhaltsvergleich 'verify' verwenden.")
    elif args.action == "verify":
        run_online(plan, args.out, args.root.expanduser(), args.max_size_mib, args.max_messages)
    else:
        run_report(plan, args.out)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Unterbrochen; bisheriger Prüfstand gespeichert.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        sys.exit(1)
