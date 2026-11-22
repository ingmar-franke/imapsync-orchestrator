# IMAP Archive Toolkit (experimental)

Add-on tools for the `imapsync-orchestrator` prototype. These tools operate on
**user-owned, previously migrated IMAP inbox and sent folders**. They are not a
standalone migration product. They require the orchestrator's completed state,
manifest, an audit SQLite index, a locally installed `imapsync` executable,
and the user's separately installed OAuth refresh helper.

> **Status:** Adapted from one historical deployment. Core algorithms have offline
> checks; these anonymized editions have **not** completed a fresh end-to-end
> production run. Do not replace your existing working scripts without a test.

## Modules

| Group | Entry points | Permission |
| --- | --- | --- |
| Archive Auditor | `archive_tools.archive_audit` | read-only IMAP, private SQLite writes |
| Delta Sync | `archive_tools.delta_inbox`, `archive_tools.delta_sent` | read-only plan/check, **APPEND** only on explicit `sync` |
| MIME Integrity Validator | `archive_tools.mime_validator`, `archive_tools.mime_detail`, `archive_tools.mime_visible` | read-only IMAP |
| Duplicate Analyzer | `archive_tools.duplicate_counts`, `archive_tools.duplicate_headers`, `archive_tools.duplicate_mime` | read-only IMAP or offline |
| Audit Diagnostics | `archive_tools.inbox_header_diagnostics`, `archive_tools.inbox_content_diagnostics` | read-only IMAP or offline |

`delta_inbox` and `delta_sent` are **separate applications and checkpoints**.

## Setup

Python 3.11+, `certifi` for legacy duplicate scans, and `imapsync` for delta transfers.
Copy `.env.archive.example` to a **private** `.env.archive` outside the
repository, set real account identifiers **only through environment variables**, and
load the file in your shell. This repository does not provide OAuth credentials,
token generators, or the organization-specific `oauth-refresh` wrapper.

**Folder mapping:** Source and target may use different IMAP folder names.
Set `IMAP_SOURCE_SENT_FOLDER` / `IMAP_TARGET_SENT_FOLDER` and, if needed,
`IMAP_SOURCE_INBOX_FOLDER` / `IMAP_TARGET_INBOX_FOLDER` independently.
The delta tools use imapsync's explicit `--f1f2 source=target` mapping when
needed. Verify the mapping using `--dry --justfolders` with a test account
before executing any `sync` operation. Older `IMAP_INBOX_FOLDER` and
`IMAP_SENT_FOLDER` single-name variables remain fallback settings.

**Compatibility:** These public modules are experimental adaptations, not
in-place upgrades for an existing private installation. The private delta
checkpoint format may be incompatible with the extra target-folder field.
Do not replace operational scripts or overwrite previous cache/state/index
files. Validate with a separate test setup first.

**No automatic publishing of mail data:** The duplicate scanner's private
CSV still contains sender/recipient/subject metadata by design; its terminal
output suppresses subjects. MIME duplicate reports use hashed filenames.
Generated CSV/JSON reports, SQLite databases and logs must remain private.

```bash
python3 -m archive_tools.archive_audit --help
python3 -m archive_tools.archive_audit index-status
python3 -m archive_tools.delta_inbox plan
python3 -m archive_tools.delta_sent plan
python3 -m archive_tools.mime_validator plan
python3 -m archive_tools.duplicate_counts --help
python3 -m archive_tools.inbox_header_diagnostics --help
```

Run `plan`/`status` first. `sync` in the delta modules is an explicit **write**
operation to the destination mailbox, not a dry run. Back up state/cache
first; never launch parallel orchestrators for the same mailboxes.

## Safety, privacy and limitations

- Source and target credentials, authentication tokens, cache files, migration
  state, SQLite indexes, UID lists, logs and private reports **must never be
  committed**. Some private reports contain clear-text metadata, including
  senders, recipients and subjects. Default terminal output of the duplicate
  tools suppresses subjects. The detailed header CSV and the optional
  extra-target report remain sensitive and must be treated as private.
- IMAP `RFC822.SIZE` sometimes differs from `BODY[]` length due to server-side
  conversion. This remains an evidence-quality warning. Decoded MIME matching
  does not establish archival byte-for-byte identity.
- Header equality, message counts and duplicates do not alone prove all
  messages or attachments were migrated. Missing/removed source UIDs need a
  separate evidence chain. Only the originally configured folders are in scope.
- Existing migration evidence is not modified by the analysis programs.
- All paths are resolved outside the repository by default. Never share a
  real `.env.archive`, private data file, or production log in an issue/PR.

## Tests

```bash
python3 -m compileall -q archive_tools
python3 -m unittest discover -s tests/archive_tools -v
python3 scripts/check_archive_release.py
```

This repository includes **no production messages, mailbox identifiers,
real hostnames, original UID snapshots or audit reports**.
