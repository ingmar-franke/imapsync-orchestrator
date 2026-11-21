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

## Four-worker continuation (v2.9; opt-in)

`imap_orchestrator_v2_9.py` is a separately published, generalized implementation
of the four-worker continuation. It **does not replace** the original bootstrap
workflow. Prepare a schema-2 state using `imap_orchestrator.py` with `plan`,
`pilot`, `pilot-check`, and a successfully completed `parallel-probe` before
switching. A migrated schema-3 state **cannot be read by the original script**.

The new module keeps previously touched packets bound to their existing
`cache-worker1` / `cache-worker2` UID caches; only verified untouched packet
ranges may be assigned to new `cache-worker3` / `cache-worker4` caches. The
upgrade backs up the old state and atomically stores the new cache-lane plan.
The requested `--workers 4` is a maximum, not four constantly active sessions:
progressive throughput measurement selects 2, then optionally 3 and 4;
server-throttle or memory warnings can reduce concurrency without erasing
checkpoints. The measurement window is deliberately approximate, not a
performance guarantee.

All account settings are read from the **same environment variables** as the
bootstrap script. Run `selftest` offline and then, on a test mailbox first:

```sh
python3 imap_orchestrator_v2_9.py selftest
python3 tests/test_v2_9.py
python3 imap_orchestrator_v2_9.py doctor
python3 imap_orchestrator_v2_9.py recover --workers 4
python3 imap_orchestrator_v2_9.py status
python3 imap_orchestrator_v2_9.py audit
```

For this module, an absent `IMAP_ALLOWED_MISSING_UIDS` or empty value means
**no historical UID gaps are tolerated**. If source messages disappear during
migration, the default action is to stop rather than rewrite the UID snapshot.
Only after a separate, documented verification may a specific UID be listed
(e.g. `IMAP_ALLOWED_MISSING_UIDS="101,205"` uses **synthetic** values).
The original snapshot digest must still match exactly after reconstruction;
these exceptions remain explicitly unresolved in the audit and are never
counted as transferred. A clean audit additionally requires stable UIDVALIDITY,
all packets complete, and expected destination message counts. It does not
prove byte-level equality of messages or attachments.

**Operational warning:** This is an offline-tested prototype. Running multiple
orchestrators simultaneously against the same state/target is prohibited;
inspect the existing process and allow the previous instance to stop cleanly.
No real mailbox, UID exceptions, logs or state from a live migration are
included in the public release.

## Adaptive ten-worker continuation (v2.11; opt-in)

`imap_orchestrator_v2_11.py` extends the independently published v2.9
continuation with 1/2/5-checkpoint bundling (200/400/1000 selected messages
per imapsync process), transfer timing profiles, and a ten-lane adaptive
parallelism controller. The maximum of ten is a **limit**, not a recommended
constant. The controller compares both message and byte throughput for stages
2 through 10, and degrades under memory pressure or server throttling.
Its benchmarks are observational; message size, network and server load vary.

**One-way cache-plan change:** An existing v2.9/v2.10 schema-3 migration can
upgrade from four assigned cache lanes to ten. The script verifies the original
snapshot and cache provenance first, backs up state, and reallocates only
untouched packets to additional cache workers. Already-touched packets retain
their assigned imapsync caches. Never run v2.9/v2.10 against a state whose
`cache_lane_plan.version` is 2. Do not delete cache directories or run versions
simultaneously. Stop the older orchestrator cleanly before changing versions.

This public build reads the same `IMAP_*` environment variables as v2.9;
`IMAP_ALLOWED_MISSING_UIDS` defaults to empty. No private account addresses,
server endpoints, real UID exceptions, runtime state or access tokens are
included. The source password is prompted; the external OAuth helper is still
required. **Do not substitute the public script for a private configured
script without checking the environment and live state.**

```sh
python3 imap_orchestrator_v2_11.py selftest
python3 tests/test_v2_11.py
python3 imap_orchestrator_v2_11.py doctor
python3 imap_orchestrator_v2_11.py recover --workers 10 --bundle-chunks 5
python3 imap_orchestrator_v2_11.py status
python3 imap_orchestrator_v2_11.py profile
python3 imap_orchestrator_v2_11.py audit
```

This prototype has **offline mock tests only**; performance, rate limits,
message correctness, and attachment integrity require live validation.

## Privacy of the published files

The source, comments, documentation, examples, and tests contain generic settings
and synthetic fixtures. Actual account names, credentials, mail contents,
mailbox exports, migration state, and process logs are not included.

By default, `.gitignore` ignores everything except the explicitly reviewed project
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
