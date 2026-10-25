### Fixed: a finding loses its KEV flag when its CVE leaves the KEV catalog

- The priority classifier only ever set `findings.is_in_kev`. A CVE removed from the KEV catalog, or a finding whose CVE changed, kept the flag, the KEV exploitation floor (P0/P1), the KEV deadline cap and the KEV dashboard count, and the intel refresh requeued its asset on every run because the flag never matched the catalog.
- The classifier now clears the flag and the KEV due date when the lookup succeeded and the CVE is not in the catalog. A failed lookup keeps the stored value. The SLA deadline set while the finding was KEV stays (deadlines only tighten).
