### Added: host discovery stage (`discover.hosts`)

- New workflow stage `discover.hosts` (T1): finds the live addresses of addresses and ranges with light probes before deeper scans, and reports each as an `ip_address` with the probe that answered. It is the `cidr → ip` adapter; chunks hold at most 64 targets and 4 096 addresses (RFC-088 step 5).
- naabu runs it only for a step that names the capability; a step that pins naabu without it is still a port scan, and a naabu report that names no capability is still bound to `scan.ports`. Sensors need the naabu with `discover.hosts@1` (sensor release after #233) to claim such steps.
- ctis is bumped to the taxonomy with `discover.hosts@1`.
