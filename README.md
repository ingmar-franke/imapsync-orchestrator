# IMAP Orchestrator (prototype)

Restartable IMAP inbox migration with UID checkpoints, optional parallel workers,
and macOS memory monitoring. Uses the separately installed
[`imapsync`](https://imapsync.lamiral.info/) executable.

**Status:** This generalized prototype has offline tests, but has not been
validated against a fresh production mailbox. Test with non-production accounts
and independently verify the destination. No automatic deletion is performed.

## Requirements and configuration

- Python 3.11+, `certifi`, `imapsync` in `PATH`, and macOS for memory telemetry.
- The source password is requested interactively and passed through a private
  temporary file. The target uses a separately supplied Microsoft 365 OAuth
  refresh helper and access token file. The helper is not included; it must
  support `--refresh` and update the configured token file.
- Copy `.env.example` to a private `.env` and edit it. The program reads
  **environment variables** and does not automatically load `.env`.
  Load your own file in a private shell with `set -a; source .env; set +a`.
- Keep `IMAP_WORK_DIR` and the token file outside the source code directory.
  The program rejects these paths when they are inside that directory.
- Preserve `migration.json`, the UID manifest, and the worker caches between
  runs. Never run two independent orchestrators against the same target/state.

## Offline checks

```sh
python3 -m pip install -r requirements.txt
python3 imap_orchestrator.py selftest
python3 tests/test_config.py
python3 imap_orchestrator.py memcheck
```

## Migration workflow

```sh
python3 imap_orchestrator.py doctor  # read-only connection check
python3 imap_orchestrator.py plan    # read-only source UID snapshot
python3 imap_orchestrator.py pilot
python3 imap_orchestrator.py pilot-check
```

Review your setup before selecting `run-safe`, `recover`, or `resume-smart`.
Run `audit` after all planned packets finish, then verify message contents and
attachments independently. The destination INBOX must be empty before the first
plan. Both mailboxes' UIDVALIDITY values must remain stable.

## Privacy of the published files

The source, comments, documentation, examples, and tests contain generic settings
and synthetic fixtures. Actual account names, credentials, mail contents,
mailbox exports, migration state, and process logs are not included.

By default, `.gitignore` ignores everything except the six reviewed project
files. Forced additions and API uploads can bypass these rules. Always inspect
the exact staged files before committing. Ignore rules do not remove files
already tracked or contained in earlier commits.

**Runtime output is private and is not automatically anonymized.** It can contain
server/account identifiers, local paths, UIDs, counts, and backend errors.
The state and imapsync caches contain mailbox metadata. Never upload these files
or terminal screenshots as issue attachments. Review and redact any diagnostic
excerpt before sharing it. OAuth helper output is suppressed on a nonzero exit;
this is not a general guarantee that every external error is sanitized.

For published commits, use a GitHub `noreply` email for both author and committer,
and inspect the commit metadata before pushing. The repository owner's public
GitHub account remains identifiable.

## Limitations

- A count/UID audit is not a byte-for-byte comparison of bodies or attachments.
- An interrupted append can leave an uncertain destination copy. Keep the
  caches and reconcile the destination; do not assume automatic exactly-once
  delivery or delete apparent duplicates without inspecting them.
- Memory telemetry is specific to macOS. Offline tests do not establish the
  safety or throughput of an unattended production run.
- No license has been selected for this prototype yet.
