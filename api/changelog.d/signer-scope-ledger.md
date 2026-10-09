### Security: the job signer signs only inside the scope people approved

- The job signer (`openctem-signer`) keeps its own scope ledger: per
  organization, the scope entries in effect (pattern, tier ceiling, expiry)
  and the target exclusions, in a hash-chained `ledger.log` in its state
  directory. The application database is never read. A job whose target is
  outside the ledger, above the approved tier or excluded is refused
  (`out_of_ledger`, `tier_exceeds_ledger`, `target_excluded`); the command
  fails with `SIGNER_REFUSED` and is not offered again (RFC-040 §11.5).
- Every scope change goes to the signer from the scope service: a widening
  (new or re-activated entry, higher tier, later expiry, exclusion removed or
  shortened) before it is saved, and it fails with `409 SCOPE_LEDGER_REFUSED`
  or `409 SCOPE_LEDGER_UNAVAILABLE` when the signer does not accept it; a
  narrowing after it is saved, never blocked. The signer checks the approval
  rule again: the organization's approval count, never the requester, at
  least one for t2, and the operator floor `SIGNER_LEDGER_MIN_APPROVALS`. A
  sync every 10 minutes narrows the ledger to the database; it never widens
  it.
- New metrics `openctem_signer_refusals_total{reason}` and
  `openctem_signer_ledger_feed_total{kind,outcome}`; new alerts
  `SignerOutOfLedger` (critical, detection A10), `SignerRefusals` and
  `SignerLedgerChangeRefused`, routed as security signals that an API outage
  does not hide.
- Only with the job signer (`SIGNER_SOCKET`); no migration.
- **Upgrade note:** a signer that signed before this release starts in
  `audit` mode (it signs and records what it would refuse). Bootstrap the
  ledger, then it enforces: `./server -signer-ledger-export /tmp/ledger.json`
  in the API container, review the file, stop the signer and run
  `openctem-signer ledger import -file` with it (steps in
  `docs/architecture/job-signing.md`, "Scope ledger"). A new signer enforces
  at once: run the same ceremony before the first scan, or every job is
  refused. `SIGNER_LEDGER=enforce|audit|off` overrides the default.
