# Changelog

## v2.11 (proposed)

- Add optional, one-way migration from four fixed cache lanes to up to ten.
  Already-touched packets retain their cache ownership and 200-mail checkpoints.
- Add bundling of 1, 2, or 5 checkpoints per imapsync process, with atomic
  checkpoint confirmation after successful log verification.
- Add measured transfer timing, a read-only profile command, and adaptive
  evaluation of worker counts 2..10 based on messages/s and bytes/s.
- Rework handling of a successful retry after transient transfer failure.
- Add synthetic offline tests for restart, cache provenance, incomplete source
  snapshots, ten-lane redistribution, memory degradation and redacted configuration.

Previous implementation remains accessible as `imap_orchestrator_v2_9.py`.
No data migrations or credentials are included in the source repository.
