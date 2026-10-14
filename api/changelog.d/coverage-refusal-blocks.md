### Fixed: a refused coverage batch is blocked, not retried every minute

- The coverage loop left the zone routing to the scan trigger, so one target
  no scan zone could place refused the whole batch (`NO_ZONE_COVERAGE`) and
  the loop retried it every pass. The scope gate now routes zones for a
  coverage batch, so such a target is refused on its own (`zone_none`,
  `zone_no_sensor`) and blocked in the ledger while the rest runs. A batch
  the trigger still refuses as a whole (a domain refusal: zone coverage,
  approval, a scan that may not run) blocks its pairs with the code, checked
  again after 6 hours; any other error leaves them due.
