### Added: bug-bounty programs (import, re-import, pause, resume, end)

- `/api/v1/programs` (RFC-065): paste a program scope or its CSV/TSV export, preview what it creates (entries, program exclusions, refusals by the platform guardrails, overlaps with the organization own scope), and import it with an attestation of the terms hash. Program entries take effect without an approver, authorize at most t1 (t0 when the program forbids automated scanning) and are audited (`bounty_program.*`). Import, re-import and resume need a recent re-authentication.
- Callers see only the programs whose group has them, unless they have full data access; another program answers 404.

### Behaviour change: scope entries record their authorization source

- `POST /scope/targets` takes `authorization_source` (`ownership` by default, or `self_attestation`); `program` is refused (`PROGRAM_ENTRY_VIA_PROGRAMS`). Responses carry `authorization_source` and `program_id`.
- Widening a program entry on the Scope routes (activate, tier, expiry, reason, discovery) answers `409 PROGRAM_MANAGED`; deactivating and deleting still work.
