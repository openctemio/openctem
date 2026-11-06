### Changed: New and Edit Scan Targets step is balanced and can pick from the scope

- The Targets step shows what you scan on the left (the targets field, "Paste or upload a list",
  "From assets or groups", "From scope") and, on the right, what the scan probes grouped by kind (domains,
  wildcards, address ranges, IP addresses, URLs, assets, asset groups) with each target's scope answer.
- Each setting sits next to the group it applies to and appears only when that group exists: the coverage
  level by the domains, how ranges are scanned by the ranges, and the options of what a run resolves again
  (with a one-line summary) under the groups. Both choices are compact segments with the chosen option
  explained on one line.
- "From scope" lists the organization's active in-scope domains, wildcards, addresses and ranges, with
  search, multi-select and "Add all in-scope entries". A wildcard entry becomes a `*.domain` target and a
  range a range target; name patterns cannot be picked and entries about to expire are flagged. It is shown
  only to people who can read the scope, and every picked target still passes the scope check.

### Fixed: New Scan said "Ranges: swept whole" for ranges that are scanned live hosts first

- A new scan with an address range showed "Ranges: swept whole" in its options summary while the API
  saves it as live hosts first. The choice shown and the summary now follow the API's rule: live hosts
  first for a new scan that can run it, every address (with live hosts first disabled and the reason) for a
  workflow without a Host discovery step, and every address for a saved scan without a choice.
