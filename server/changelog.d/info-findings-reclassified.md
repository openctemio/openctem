### Added: stored info matches of template scanners move to exposures

- New closure reason `reclassified_exposure` (resolved, verification `none`): a finding the platform moved to its asset's exposures. It never counts as fixed (MTTR, fix rate, the Fixed lens).
- `refingerprint -info-exposures [-tenant <id>] [-apply] [-down]` moves the open informational findings of template scanners (nuclei) filed before info matches became exposures, exactly as ingest moves a new match: the same exposure event, the finding resolved as `reclassified_exposure`, severity `none` mapped to `info`, a timeline entry per finding and one `findings.reclassified` audit entry per tenant. Findings on a ticket, in a remediation task or with a pending decision are held. Dry run by default; `-down -apply` undoes it.

### Fixed: covered scans no longer close info findings as fixed

- A covered nuclei scan whose info matches went to exposures no longer auto-resolves the informational findings of that tool as fixed: it never reports them as findings, so their absence proves nothing.

### Fixed: closures for an out-of-scope asset no longer count as fixed in dashboards

- `RemediatedSQL` left `out_of_scope` closures in the fixed counts while `CountsAsRemediated` left them out; both now leave out every obsolete reason.
