### Behaviour change: address ranges are scanned live hosts first

- New `target_options.cidr_mode` value `liveness`, the default of a new scan with an address range when it can run it (a single-scanner scan, or a workflow with a Host discovery step). The ranges go to Host discovery and passive lookups only; the port scan and the steps after it get the live hosts found plus the addresses the inventory already holds in the ranges (RFC-088 step 6).
- A scan saved before keeps sweeping every address until it is edited. An explicit `sweep` is now stored as chosen. An explicit `liveness` on a workflow without Host discovery is refused (`LIVENESS_NEEDS_HOST_DISCOVERY`).
- The Network starter workflow starts with a Host discovery step; copies made before keep their steps. A run of names settles Host discovery without a command.
- The platform names the probe ports of every host discovery job (80, 443, 22, 3389, 8080, 8443 unless the step sets `ports`).
- New Scan: the address ranges choice offers "Find live hosts first" (en, vi).
