### Added: exploration rules open leads

- Three deterministic rules open exploration leads in each organization's continuous exploration:
  `dns.takeover_check` (an active dangling alias found by the platform's DNS check, not yet found
  claimable), `version.confirm` (an open KEV or critical version-match finding whose match is only
  potential) and `asset.gone_with_findings` (an asset the liveness ledger holds gone while findings
  stay open). Each lead cites its evidence (`derived_from` links) and is audited
  (`exploration.lead_opened`, actor `rule:<type>@<version>`).
- Passive steps open at once; active steps open at once only while automatic coverage is on,
  otherwise they wait for approval. Caps: 5 live leads per asset, 500 per exploration. A closed
  question is not asked again for 30 days. Nothing dispatches yet.
