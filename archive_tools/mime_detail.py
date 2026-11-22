#!/usr/bin/env python3
"""Read-only, per-message MIME part and metadata differential diagnosis.

Requires an existing MIME progress report. Does not save message bodies."""
from __future__ import annotations
from archive_tools import config as cfg

import argparse
from collections import Counter
from datetime import datetime, timezone
from difflib import SequenceMatcher
from email import policy
from email.parser import BytesParser
import getpass
import hashlib
from pathlib import Path
import sys
import unicodedata

from archive_tools.mime_validator import (
    DEFAULT_OUT, DEFAULT_ROOT, FOLDER, TARGET_FOLDER, load_json, load_plan,
    private_write, verified_fetch_one, sha,
)
from archive_tools.archive_audit import (
    ResilientReadOnlySession, source_login, target_login, state_and_manifest,
    packet_progress, completed_migration_lock, digest_uids,
)

DEFAULT_GROUPS = (1,)
HEADER_FIELDS = ("message-id", "date", "from", "to", "cc", "bcc", "subject", "reply-to",
                 "in-reply-to", "references", "mime-version", "content-type",
                 "content-transfer-encoding", "content-disposition")


def norm_text(part, decoded: bytes) -> str | None:
    if not part.get_content_maintype().lower() == "text":
        return None
    try:
        charset = part.get_content_charset() or "utf-8"
        txt = decoded.decode(charset, errors="replace")
    except (LookupError, UnicodeError, TypeError):
        return None
    return unicodedata.normalize("NFC", txt.replace("\r\n", "\n").replace("\r", "\n"))


def header_digest(message, field: str) -> str | None:
    vals = message.get_all(field, [])
    if not vals:
        return None
    normalized = [" ".join(str(v).split()) for v in vals]
    return sha("\n".join(normalized).encode("utf-8", errors="surrogateescape"))


def inspect_message(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    parts = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            # Fail closed; never call undecodable leaf content equal.
            raise ValueError("MIME-Blatt ohne dekodierbare Nutzdaten")
        kind = "text" if part.get_content_maintype() == "text" and part.get_content_disposition() != "attachment" else "attachment_or_other"
        filename = part.get_filename()
        normalized = norm_text(part, payload)
        parts.append({
            "index": len(parts) + 1,
            "kind": kind,
            "type": part.get_content_type(),
            "disposition": part.get_content_disposition() or "",
            "filename_sha256_prefix": sha(filename.encode("utf-8"))[:12] if filename else None,
            "transfer_encoding": part.get("Content-Transfer-Encoding", "").lower(),
            "payload_bytes": len(payload),
            "payload_sha256": sha(payload),
            "normalized_text_sha256": sha(normalized.encode("utf-8")) if normalized is not None else None,
            "text_characters": len(normalized) if normalized is not None else None,
            "_normalized_text": normalized,
        })
    return {
        "raw_sha256": sha(raw),
        "headers": {field: header_digest(msg, field) for field in HEADER_FIELDS},
        "parts": parts,
    }


def clean_result(record: dict) -> dict:
    return {"raw_sha256": record["raw_sha256"], "headers": record["headers"],
            "parts": [{k: v for k, v in p.items() if k != "_normalized_text"}
                      for p in record["parts"]]}


def one_to_one_diff(src: dict, dst: dict) -> dict:
    sp = src["parts"]
    tp = dst["parts"]
    sh = {k for k in HEADER_FIELDS if src["headers"].get(k) != dst["headers"].get(k)}
    fields_changed = sorted(sh)
    src_payloads = Counter(p["payload_sha256"] for p in sp)
    dst_payloads = Counter(p["payload_sha256"] for p in tp)
    src_kinds = Counter((p["type"], p["kind"]) for p in sp)
    dst_kinds = Counter((p["type"], p["kind"]) for p in tp)
    paired_by_index = []
    for a, b in zip(sp, tp):
        same_payload = a["payload_sha256"] == b["payload_sha256"]
        same_normalized_text = (a["normalized_text_sha256"] is not None and
                                a["normalized_text_sha256"] == b["normalized_text_sha256"])
        same_type = a["type"] == b["type"]
        sim = None
        if (a["_normalized_text"] is not None and b["_normalized_text"] is not None
                and not same_normalized_text):
            aa, bb = a["_normalized_text"], b["_normalized_text"]
            sim = round(SequenceMatcher(None, aa[:10000], bb[:10000], autojunk=True).ratio(), 4)
        paired_by_index.append({
            "index": a["index"], "source_type": a["type"], "target_type": b["type"],
            "source_bytes": a["payload_bytes"], "target_bytes": b["payload_bytes"],
            "same_payload": same_payload, "same_type": same_type,
            "same_normalized_text": same_normalized_text,
            "text_similarity_first_10000_chars": sim,
            "same_filename_hash": a["filename_sha256_prefix"] == b["filename_sha256_prefix"],
            "same_disposition": a["disposition"] == b["disposition"],
            "same_transfer_encoding": a["transfer_encoding"] == b["transfer_encoding"],
        })
    if src["raw_sha256"] == dst["raw_sha256"]:
        outcome = "IDENTISCHE_ROHDATEN"
    elif src_payloads == dst_payloads:
        if src_kinds == dst_kinds:
            outcome = "IDENTISCHE_NUTZDATEN_MIME_ODER_HEADER_DIFFERENZ"
        else:
            outcome = "IDENTISCHE_NUTZDATEN_ABER_MIME_TYP_ODER_ROLLE_ANDERS"
    elif len(sp) == len(tp) and all(
        a["payload_sha256"] == b["payload_sha256"] or
        (a["normalized_text_sha256"] is not None and
         a["normalized_text_sha256"] == b["normalized_text_sha256"])
        for a, b in zip(sp, tp)
    ):
        outcome = "NUR_TEXTNORMALISIERUNG_ODER_MIME_METADATEN"
    else:
        outcome = "NUTZDATEN_UNTERSCHIEDLICH" if src_kinds == dst_kinds else "MIME_STRUKTUR_ODER_NUTZDATEN_ABWEICHEND"
    return {
        "classification": outcome,
        "source_parts": len(sp), "target_parts": len(tp),
        "payload_hashes_same_multiset": src_payloads == dst_payloads,
        "mime_types_and_roles_same_multiset": src_kinds == dst_kinds,
        "changed_headers": fields_changed,
        "parts_by_position": paired_by_index,
    }


def parse_groups(arg: str) -> list[int]:
    try:
        values = [int(x.strip()) for x in arg.split(",")]
    except ValueError as exc:
        raise ValueError("--groups benötigt kommagetrennte Zahlen, z. B. 1,2,3") from exc
    if not values or len(values) > 30 or any(x <= 0 for x in values) or len(set(values)) != len(values):
        raise ValueError("--groups: 1 bis 30 eindeutige positive Gruppennummern")
    return values


def run(out: Path, root: Path, groups: list[int], max_size_mib: int, output_path: Path) -> None:
    plan = load_plan(out / "header_index.sqlite3")
    indexed = {x["group"]: x for x in plan["cases"]}
    missing = [x for x in groups if x not in indexed]
    if missing:
        raise ValueError(f"Gruppe(n) nicht im vollständigen Headerindex: {missing}")
    prior = load_json(out / "sent_mime_progress.json")
    if not prior or prior.get("plan_digest") != plan["plan_digest"]:
        raise RuntimeError("Vorherige MIME-Fortschrittsdatei fehlt oder Planprüfsumme stimmt nicht")
    report = load_json(out / "sent_mime_report.json")
    if not report or report.get("plan_digest") != plan["plan_digest"]:
        raise RuntimeError("Vorheriger MIME-Bericht fehlt oder Planprüfsumme stimmt nicht")
    report_groups = {x["group"]: x for x in report["groups"]}
    if any(x not in report_groups for x in groups):
        raise RuntimeError("Eine ausgewählte Gruppe fehlt im MIME-Bericht")
    selected = [indexed[g] for g in groups]
    total_octets = sum(int(row["size"]) for c in selected for side in ("source", "target")
                        for row in c[side] if row["size"] is not None)
    print(f"DETAILPRÜFUNG: {groups}; {sum(len(c[s]) for c in selected for s in ('source','target'))} UID-Inhalte, "
          f"geplantes RFC822.SIZE-Volumen {total_octets / (1024*1024):.2f} MiB", flush=True)
    state, rows = state_and_manifest(root)
    packet_status = packet_progress(state, rows)
    if not packet_status["all_packets_processed"]:
        raise RuntimeError("Migrationsstatus nicht abgeschlossen")
    src_user, dst_user = state.get("user1"), state.get("user2")
    if not src_user or not dst_user:
        raise RuntimeError("Quell- oder Zielkonto nicht im Migrationsstatus")
    examined = {"source": {}, "target": {}}
    cap = max_size_mib * 1024 * 1024
    with completed_migration_lock(root, packet_status):
        for side in ("source", "target"):
            password = getpass.getpass("Quell-IMAP-Passwort: ") if side == "source" else None
            opener = (lambda: source_login(src_user, password)) if side == "source" else (lambda: target_login(dst_user))
            session = ResilientReadOnlySession(opener, FOLDER if side == 'source' else TARGET_FOLDER, side)
            try:
                count, validity, uids = session.start()
                meta = plan["index_sides"][side]
                if (count != meta["n_uids"] or str(validity) != str(meta["uidvalidity"])
                        or digest_uids(uids) != meta["uid_list_sha256"]):
                    raise RuntimeError(f"{side}: UID-Snapshot verändert; Audit wird abgebrochen")
                print(f"{side}: UID-Snapshot unverändert ({count:,}); gezielter Abruf", flush=True)
                for case in selected:
                    for entry in case[side]:
                        uid = int(entry["uid"])
                        expected = entry["size"]
                        if expected is None or expected > cap:
                            raise RuntimeError(f"UID {uid}: fehlende oder zu große Nachricht; Limit {max_size_mib} MiB")
                        size, raw, mismatch = verified_fetch_one(session, uid, expected)
                        last = prior["results"][side].get(str(uid))
                        if not last or last.get("status") != "ok" or sha(raw) != last.get("raw_sha256"):
                            raise RuntimeError(f"{side} UID {uid}: Inhalt seit V1.2 verändert oder Prüfnachweis fehlt")
                        rec = inspect_message(raw)
                        del raw
                        rec["rfc822_size"] = size
                        rec["size_discrepancy"] = mismatch
                        examined[side][uid] = rec
                        print(f"  {side} UID {uid}: {len(rec['parts'])} MIME-Teile geprüft", flush=True)
            finally:
                session.close()
                password = None
    results = []
    for case in selected:
        sn = [(row["uid"], examined["source"][row["uid"]]) for row in case["source"]]
        dn = [(row["uid"], examined["target"][row["uid"]]) for row in case["target"]]
        pairs = []
        for suid, sr in sn:
            for duid, dr in dn:
                pairs.append({"source_uid": suid, "target_uid": duid,
                              **one_to_one_diff(sr, dr)})
        all_src_variants = len(set(tuple((p["type"], p["payload_sha256"]) for p in r["parts"]) for _, r in sn))
        print(f"\nGRUPPE {case['group']}: Quelle {len(sn)} / target IMAP {len(dn)}, "
              f"Quellvarianten nach Teilen: {all_src_variants}")
        for pair in pairs:
            print(f"  {pair['source_uid']} -> {pair['target_uid']}: {pair['classification']}")
            if pair["changed_headers"]:
                print("    Andere Headerfelder: " + ", ".join(pair["changed_headers"]))
            if pair["source_parts"] != pair["target_parts"]:
                print(f"    MIME-Teilezahl verschieden: {pair['source_parts']} / {pair['target_parts']}")
            for part in pair["parts_by_position"]:
                status = ("gleich" if part["same_payload"] else
                          "Text-normalisiert gleich" if part["same_normalized_text"] else "ABWEICHEND")
                sim = (f"; Textähnlichkeit {part['text_similarity_first_10000_chars']:.1%}"
                       if part["text_similarity_first_10000_chars"] is not None else "")
                meta_changed = []
                if not part["same_filename_hash"]:
                    meta_changed.append("Dateiname")
                if not part["same_disposition"]:
                    meta_changed.append("Disposition")
                if not part["same_transfer_encoding"]:
                    meta_changed.append("Transfer-Encoding")
                extra = ("; MIME-Metadaten anders: " + ", ".join(meta_changed)) if meta_changed else ""
                print(f"    Teil {part['index']}: {part['source_type']} / {part['target_type']}, "
                      f"{part['source_bytes']} / {part['target_bytes']} Bytes: {status}{sim}{extra}")
        results.append({
            "group": case["group"],
            "previous_status": report_groups[case["group"]]["status"],
            "source": {str(uid): clean_result(r) for uid, r in sn},
            "target": {str(uid): clean_result(r) for uid, r in dn},
            "source_part_variants": all_src_variants,
            "pairwise_comparisons": pairs,
        })
    if output_path.is_symlink() or output_path.parent != out:
        raise RuntimeError("Ausgabedatei muss regulär im Audit-Verzeichnis liegen")
    private_write(output_path, {
        "schema": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "folder": FOLDER,
        "plan_digest": plan["plan_digest"],
        "groups": results,
        "caveat": "Belege betreffen die aktuell via IMAP ausgelieferten Inhalte. "
                  "Keine ursprüngliche Byte-Archivtreue nachgewiesen. Kein E-Mail-Text gespeichert.",
    })
    print(f"\nDiagnose gespeichert: {output_path}")
    print("Nur EXAMINE/UID SEARCH/UID FETCH BODY.PEEK[]; keine Mails verändert oder kopiert.")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--groups", default=",".join(str(i) for i in DEFAULT_GROUPS))
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    p.add_argument("--max-size-mib", type=int, default=30)
    args = p.parse_args()
    if args.max_size_mib < 1 or args.max_size_mib > 30:
        p.error("--max-size-mib zwischen 1 und 30")
    groups = parse_groups(args.groups)
    out = args.out.expanduser()
    if out.is_symlink():
        p.error("Audit-Verzeichnis darf kein Symlink sein")
    filename = "sent_mime_detail_" + "_".join(map(str, groups)) + ".json"
    run(out, args.root.expanduser(), groups, args.max_size_mib, out / filename)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Unterbrochen. Bestehende Migrations- und Auditdaten unverändert.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        sys.exit(1)
