### Behaviour change: scope changes left waiting for approval take effect where approvals are off

- Scope entries and exclusions still pending in an organization whose scan approval mode is Off or On (created before approvals of scope changes were limited to Strict) are put into effect by the new hourly `scope-pending-settle` controller. Each row goes through the job signer's ledger before it is saved and is audited (`scope_target.activated` / `scope_exclusion.activated`, actor `system`, reason `approvals_not_required`); administrators get one notification per organization. Strict organizations, and any whose mode cannot be read, keep their pending rows. No migration rewrites rows (a SQL update would bypass the signer's ledger).
- Activating such a pending entry or exclusion puts it into effect at once outside Strict.
- The Approvals tab and the "Waiting for approval" strip item are shown only while the organization requires approvals or something still waits. The In scope list now shows pending entries, and the Out of scope list pending and rejected exclusions, each with its status pill.

### Fixed: adding a scope entry that already exists names the existing one

- Adding an entry or exclusion whose pattern the organization already has answers `409 SCOPE_ENTRY_EXISTS` / `SCOPE_EXCLUSION_EXISTS` with `details: {id, status}` of the existing row (tenant-scoped lookup, never another organization's row). The add dialogs say what the existing row is (waiting for approval, deactivated, expired, rejected, in effect) and offer the fitting action: approve or put in effect, activate, renew, or open it. Review-rule previews return the same code with `existing`.
