### Behaviour change: results outside a scan job's targets are recorded, not dropped

- A sensor result for a host outside its command's targets (a host a template scanner reached after a redirect, an address a port scan found that no target name states) or outside an address-only command's addresses is now recorded: a new asset is created as a scan discovery, an existing one is only marked seen, and its findings are stored. Recording grants nothing: the active-scan gate still decides what may be probed, so a third-party or shared host stays passive until a person puts it in scope.
- Findings on such assets send no notifications, open no tickets and are routed to no group, and the run does not count those assets as covered, so absence never closes their other findings.
- One report records at most 1000 such assets; the rest are refused with their findings (`assets_over_cap`, `findings_over_cap`, item error `too_many`, receipt item `over_cap`). The `sensor.results_outside_job` audit entry now reports what was recorded and what was refused (severity medium, high when the cap refused some).

### Changed: provider edge addresses are recorded as the provider's

- A new address a scan finds inside a range a provider publishes for a front end many organizations share (for example a cloud front door's IPv6 range) gets the attribution state `dependency` with the rule `provider_shared_front_end`: recorded and watched passively, never the organization's own internet-facing asset, never raised by automation. The names that resolve to it stay the organization's.

### Fixed: services on a scan job's own target hosts were dropped

- A port scan of a host-scoped job lost every service it found on the target's addresses: the stored service name was not split into its host, so each service read as outside the job's targets.
- An address-only command's out-of-range assets were dropped without an audit entry and their findings were labelled as outside the uploader's scope.
