#!/usr/bin/env python3
"""Read-only HTML visible-text, link-target and attachment hash comparison.

HTMLParser is an approximation, not a browser renderer. No message texts or
attachment contents are stored in the report."""
from __future__ import annotations
from archive_tools import config as cfg

import argparse
from collections import Counter
from datetime import datetime, timezone
from difflib import SequenceMatcher
from email import policy
from email.parser import BytesParser
import getpass
from html.parser import HTMLParser
import re
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
EXCLUDED = {"script", "style", "head", "template", "svg", "noscript"}
BLOCKS = {"br", "p", "div", "li", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "blockquote", "section", "article"}
ATTRS = {"href", "src", "action"}


class ApproxVisibleHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden_stack = []
        self.chunks = []
        self.attrs = []
        self.bad = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in EXCLUDED:
            self.hidden_stack.append(tag)
        if not self.hidden_stack and tag in BLOCKS:
            self.chunks.append(" ")
        if not self.hidden_stack:
            for key, value in attrs:
                if key is not None and key.lower() in ATTRS and value is not None:
                    self.attrs.append((key.lower(), sha(value.strip().encode("utf-8"))))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() in EXCLUDED:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in EXCLUDED:
            if self.hidden_stack and self.hidden_stack[-1] == tag:
                self.hidden_stack.pop()
            else:
                self.bad = True
        elif not self.hidden_stack and tag in BLOCKS:
            self.chunks.append(" ")

    def handle_data(self, data):
        if not self.hidden_stack:
            self.chunks.append(data)

    def get(self):
        return normalize_whitespace("".join(self.chunks)), Counter(self.attrs)


def normalize_whitespace(text: str) -> str:
    return " ".join(unicodedata.normalize("NFC", text).split())


def decode_text(part, payload: bytes) -> str | None:
    try:
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    except (LookupError, TypeError):
        return None


def fingerprint_message(raw: bytes) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    bodies = []
    binary = []
    for part in message.walk():
        if part.is_multipart():
            continue
        data = part.get_payload(decode=True)
        if data is None:
            raise ValueError("MIME-Teil ohne dekodierbare Nutzdaten")
        typ = part.get_content_type().lower()
        if typ in ("text/html", "text/plain") and part.get_content_disposition() != "attachment":
            text = decode_text(part, data)
            if text is None:
                raise ValueError("Text-Encoding nicht dekodierbar")
            if typ == "text/html":
                parser = ApproxVisibleHTML()
                parser.feed(text)
                parser.close()
                if parser.bad or parser.hidden_stack:
                    raise ValueError("HTML-Ausschlussstruktur nicht eindeutig")
                visible, attrs = parser.get()
            else:
                visible = normalize_whitespace(text)
                attrs = Counter()
            bodies.append({
                "type": typ, "payload_hash": sha(data), "payload_length": len(data),
                "visible_hash": sha(visible.encode("utf-8")),
                "visible_length": len(visible),
                "attr_hashes": attrs,
                "_visible": visible,
            })
        else:
            name = part.get_filename() or ""
            binary.append((typ, part.get_content_disposition() or "", sha(name.encode("utf-8")), sha(data), len(data)))
    return {"raw_sha256": sha(raw), "bodies": bodies, "binary": Counter(binary)}


def diff_size(a: str, b: str) -> dict:
    if a == b:
        return {"same": True, "similarity_first_10000": 1.0, "inserted_characters": 0,
                "deleted_characters": 0, "replaced_characters_source": 0,
                "replaced_characters_target": 0, "change_blocks_first_10000": 0,
                "comparison_truncated": False}
    # Bounded comparison avoids potentially quadratic operations on very long HTML.
    limit = 10000
    aa, bb = a[:limit], b[:limit]
    sm = SequenceMatcher(None, aa, bb, autojunk=False)
    ins = dele = repa = repb = blocks = 0
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            continue
        blocks += 1
        if op == "insert": ins += j2-j1
        if op == "delete": dele += i2-i1
        if op == "replace": repa += i2-i1; repb += j2-j1
    return {"same": False, "similarity_first_10000": round(sm.ratio(), 5),
            "inserted_characters": ins, "deleted_characters": dele,
            "replaced_characters_source": repa, "replaced_characters_target": repb,
            "change_blocks_first_10000": blocks,
            "comparison_truncated": len(a) > limit or len(b) > limit}


def compare_messages(src: dict, dst: dict) -> dict:
    binary_match = src["binary"] == dst["binary"]
    sb, tb = src["bodies"], dst["bodies"]
    structurally_same = [v["type"] for v in sb] == [v["type"] for v in tb]
    diffs = []
    for i, (a, b) in enumerate(zip(sb, tb), 1):
        d = diff_size(a["_visible"], b["_visible"])
        d.update({"index": i, "type": a["type"],
                  "source_visible_characters": a["visible_length"],
                  "target_visible_characters": b["visible_length"],
                  "source_payload_bytes": a["payload_length"],
                  "target_payload_bytes": b["payload_length"],
                  "same_decoded_text_payload": a["payload_hash"] == b["payload_hash"],
                  "same_html_link_targets": a["attr_hashes"] == b["attr_hashes"],
                  "source_link_count": sum(a["attr_hashes"].values()),
                  "target_link_count": sum(b["attr_hashes"].values())})
        diffs.append(d)
    exact_all_visible = structurally_same and len(sb) == len(tb) and all(d["same"] for d in diffs)
    links_same = exact_all_visible and all(d["same_html_link_targets"] for d in diffs)
    if not structurally_same or len(sb) != len(tb) or not binary_match:
        verdict = "MIME_STRUKTUR_ODER_ANHANG_ABWEICHEND"
    elif exact_all_visible and links_same:
        verdict = "SICHTTEXT_UND_LINKS_GLEICH"
    elif exact_all_visible:
        verdict = "SICHTTEXT_GLEICH_ABER_LINKS_UNTERSCHIEDLICH"
    else:
        verdict = "SICHTTEXT_UNTERSCHIEDLICH"
    return {"verdict": verdict, "binary_attachments_identical": binary_match,
            "source_binary_parts": sum(src["binary"].values()),
            "target_binary_parts": sum(dst["binary"].values()),
            "same_textpart_types_order": structurally_same,
            "text_parts": diffs}


def select_groups(report: dict, args) -> list[int]:
    group_map = {g["group"]: g for g in report["groups"]}
    if args.all_open:
        return sorted(g["group"] for g in report["groups"]
                      if g["status"] == "SOURCE_CONTENT_VARIANTS_ABSENT_IN_HEADER_GROUP")
    try:
        groups = [int(n.strip()) for n in args.groups.split(",")]
    except ValueError:
        raise ValueError("--groups erfordert kommagetrennte Zahlen") from None
    if not groups or len(groups) > 30 or len(groups) != len(set(groups)) or any(g not in group_map for g in groups):
        raise ValueError("1–30 eindeutige existierende Gruppennummern nötig")
    return groups


def run(args) -> None:
    out = args.out.expanduser()
    root = args.root.expanduser()
    if out.is_symlink() or not out.is_dir():
        raise RuntimeError("Audit-Ausgabeverzeichnis fehlt oder ist Symlink")
    plan = load_plan(out / "header_index.sqlite3")
    prior = load_json(out / "sent_mime_progress.json")
    report = load_json(out / "sent_mime_report.json")
    if not prior or not report or any(x["plan_digest"] != plan["plan_digest"] for x in [prior,report]):
        raise RuntimeError("MIME-Nachweise fehlen oder Planprüfsumme stimmt nicht")
    group_ids = select_groups(report, args)
    selected = [g for g in plan["cases"] if g["group"] in set(group_ids)]
    if len(selected) != len(group_ids):
        raise RuntimeError("Eine ausgewählte Gruppe fehlt im lokalen Plan")
    cap = args.max_size_mib * 1024 * 1024
    planned = [x for g in selected for side in ("source", "target") for x in g[side]]
    if any(x["size"] is None or x["size"] > cap for x in planned):
        raise RuntimeError("Einzelne Nachrichten überschreiten Größenlimit bzw. Größe unbekannt")
    print(f"SICHTTEXT-PRÜFUNG, nur lesend: {len(selected)} Gruppen, "
          f"{len(planned)} Nachrichten, max. {args.max_size_mib} MiB je Nachricht", flush=True)
    state, rows = state_and_manifest(root)
    status = packet_progress(state, rows)
    if not status["all_packets_processed"]:
        raise RuntimeError("Migrationsstatus unvollständig")
    src_user, dst_user = state.get("user1"), state.get("user2")
    if not src_user or not dst_user:
        raise RuntimeError("Benutzernamen im Migrationsstatus fehlen")
    checked = {"source": {}, "target": {}}
    with completed_migration_lock(root, status):
        for side in ("source", "target"):
            password = getpass.getpass("Quell-IMAP-Passwort: ") if side == "source" else None
            opener = ((lambda: source_login(src_user, password)) if side == "source"
                      else (lambda: target_login(dst_user)))
            session = ResilientReadOnlySession(opener, FOLDER if side == 'source' else TARGET_FOLDER, side)
            try:
                count, validity, uids = session.start()
                meta = plan["index_sides"][side]
                if count != meta["n_uids"] or str(validity) != str(meta["uidvalidity"]) or digest_uids(uids) != meta["uid_list_sha256"]:
                    raise RuntimeError(f"{side}: UID-Snapshot seit Indexierung verändert; keine Prüfung")
                entries = [r for g in selected for r in g[side]]
                for idx, entry in enumerate(entries, 1):
                    uid = int(entry["uid"])
                    _, raw, _ = verified_fetch_one(session, uid, entry["size"])
                    evidence = prior["results"][side].get(str(uid))
                    if not evidence or evidence.get("status") != "ok" or sha(raw) != evidence["raw_sha256"]:
                        raise RuntimeError(f"{side} UID {uid}: SHA-256 stimmt nicht mit vorherigem Audit überein")
                    checked[side][uid] = fingerprint_message(raw)
                    del raw
                    if idx % 10 == 0 or idx == len(entries):
                        print(f"{side}: {idx}/{len(entries)} geprüft", flush=True)
            finally:
                session.close()
                password = None
    output = []
    for case in selected:
        group_pairs = []
        for src in case["source"]:
            for dst in case["target"]:
                a = checked["source"][src["uid"]]
                b = checked["target"][dst["uid"]]
                group_pairs.append({"source_uid": src["uid"], "target_uid": dst["uid"],
                                    **compare_messages(a, b)})
        summary = Counter(x["verdict"] for x in group_pairs)
        output.append({"group": case["group"], "source_count": len(case["source"]),
                       "target_count": len(case["target"]), "comparisons": group_pairs,
                       "pair_summary": dict(summary)})
        print(f"Gruppe {case['group']:2d}: " + ", ".join(f"{k}={v}" for k,v in sorted(summary.items())), flush=True)
    fname = "sent_sichttext_" + ("alle_offenen" if args.all_open else "_".join(map(str, group_ids))) + ".json"
    path = out / fname
    if path.is_symlink() or path.parent != out:
        raise RuntimeError("Unzulässiger Ausgabepfad")
    private_write(path, {"schema":1, "created_utc":datetime.now(timezone.utc).isoformat(),
                         "plan_digest":plan["plan_digest"], "groups": output,
                         "privacy": "Kein E-Mail-Text, keine URLs, keine Anhänge gespeichert",
                         "caveat": "Sichttext wird per HTMLParser angenähert, kein echter Browser-Render-Test. "
                                   "Unterschiede in sichtbarem Text bedeuten nicht automatisch fehlende Nachrichten. "
                                   "IMAP-gelieferte Daten, nicht Original-RFC822-Beweis. "
                                   "RFC822.SIZE-Abweichungen bleiben im separaten Vorbericht bestehen."})
    print(f"Bericht: {path}")
    print("Keine E-Mails geändert, kopiert, gelöscht. Quell-/Ziel-Snapshots unverändert.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    opts = parser.add_mutually_exclusive_group()
    opts.add_argument("--groups", default=",".join(map(str, DEFAULT_GROUPS)))
    opts.add_argument("--all-open", action="store_true", help="Alle Gruppen mit MIME-Abweichung (bis zum Sicherheitslimit)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--max-size-mib", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.max_size_mib <= 30:
        parser.error("--max-size-mib muss zwischen 1 und 30 liegen")
    run(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Abgebrochen. Postfächer unverändert.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        sys.exit(1)
