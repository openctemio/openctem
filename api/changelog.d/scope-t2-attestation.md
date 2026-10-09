### Added: long intrusive (T2) scope entries are confirmed periodically, or fall back to T1

- An active T2 entry that lasts beyond its attestation period (every 90 days by default; an owner sets 30 to 180) is confirmed by an owner, administrator or scope approver: "Keep T2 for <pattern>?" arrives in-app, by email and on the organization's channels, and the Approvals tab offers "Keep T2" (`POST /api/v1/scope/targets/{id}/attest`).
- Without a confirmation within 14 days the entry falls back to non-intrusive (T1) probes. It is never removed; raising it to T2 again is an ordinary widening that needs an approval. The downgrade is audited (`scope_target.t2_downgraded`) and announced to every administrator.
- `t2_attestation_days` joins the owner-only `PUT /api/v1/scope/settings/intrusive`. Active T2 entries answer an `attestation` object.
- Migration `001531` adds `attested_at`, `attested_by` and `attestation_requested_at` to `scope_targets`. Existing T2 entries start their first period from their approval.
