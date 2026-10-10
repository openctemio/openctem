### Added: VEX statements per organization

- `GET/POST /api/v1/vex-statements`, `GET/PATCH/DELETE /api/v1/vex-statements/{id}`: the organization states that a vulnerability does not affect a package (with a justification), affects it, is fixed in it or is under investigation; for every version, listed versions or a version range; on every asset or one asset; with an optional expiry.
- `not_affected` closes the open findings it covers as false positive, `fixed` resolves them; `affected` and `under_investigation` annotate. The statement also covers findings reported later; editing, deleting or the expiry of a statement reopens the findings it closed unless another statement covers them. Findings from pentest, manual, bug bounty and red team sources are never closed.
- `POST /api/v1/vex-statements/import` stores the statements of an OpenVEX, CSAF VEX or CycloneDX VEX document (5 MB, 5 000 statements) for one asset or every asset; `dry_run=true` previews.
- Reading needs `components:read`; writing needs `findings:approve`, the asset in the caller's scope, and full data access for a statement on every asset. Every change, expiry and closure is audited (`vex_statement.*`).
- Migration `001902_vex_statements` adds `vex_statements` and `findings.vex_statement_id` (no data change).
