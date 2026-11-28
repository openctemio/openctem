### Fixed: CTEM maturity details and turned-off connections are worded in the reader's language

- `GET /api/v1/ctem-cycles/metrics/trend` maturity components carry a stable `detail_code` next to the English `detail` (`validation_share`, `no_remediation`, `resolution_ratio`, `no_prior_cycle`, `mttr_direction`, `no_findings_opened`, `priority_churn`, `scope_reported_only`). The web words it in the reader's language; the English sentences are plain words now (no metric keys such as `findings_resolved / findings_opened`, no formulas), and the page subtitle explains the score without a Σ formula.
- Turning a connection off stores the status code `INTEGRATION_DISABLED_BY_USER` with the English message "Disabled by user at <time, UTC>", so the web shows "Turned off on <local date>" in the reader's language.
- The maturity score no longer breaks "100 / 100" over two lines.
- Docs: none (wording of existing pages; the new field is additive)
