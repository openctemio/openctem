### Security: a scan run stops when a target check is not wired

- A scan trigger (manual, scheduled, retry, workflow, quick scan) used to skip scope exclusions silently when no exclusion filter was wired, and likewise the ownership and act-scope checks. It now refuses to dispatch (fail closed), as every other dispatch path already did. Production wires all three, so a correctly configured server dispatches the same targets as before.

### Changed: the scan trigger decides its targets through the one target gate

- `resolveScanTargets` builds the candidates (direct targets, asset-group members, the scanner type gate, archived members) and calls `ResolveDispatchTargets` once for exclusions, ownership (including the takeover-only exception), the act scope, the private-range rule and the tier ceiling. Its own copies of those checks are removed. Targets, counts, warnings and refusal codes are unchanged, pinned by characterization tests.
- The gate checks the act scope before the tier ceiling on every path: a target refused by both is reported as outside the actor's scope, so an actor learns nothing about the scope entries of what they may not scan.
