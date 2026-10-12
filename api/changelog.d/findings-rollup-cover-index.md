### Changed: faster attack paths, exposure chains and dashboard rollups on large tenants

- The attack-graph node read counts every asset's findings in one aggregate
  over the tenant's findings instead of one index probe per asset.
- A new covering index, `idx_findings_tenant_rollup_cover`, replaces
  `idx_findings_tenant_stats_cover` with six more columns. The tenant-wide
  finding rollups (dashboard stats, executive summary, finding groups,
  attack-graph counts) can now run as index-only scans.
- Measured on a tenant with 110k assets and 525k findings: attack paths went
  from 3-5 s to 0.5 s, exposure chains from 3.2 s to 0.8 s, finding groups
  from 1.4 s to 0.75 s, and the dashboard overview from 4.8 s to 3.1 s.
- Upgrade note: both migrations build and drop the index `CONCURRENTLY`, so
  the findings table stays writable. The build reads the whole table once
  (about 1 s per million findings on the test host).
