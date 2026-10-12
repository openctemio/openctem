### Fixed: a wildcard pattern is no longer sent to an active scanner as a target

- A target such as `*.example.com` is a set of hosts, not a host. It was accepted as a scan target and dispatched as is, so an active scanner (nuclei) received a name it could not resolve and the sensor refused the job.
- Creating, editing, quick-scanning or triggering a scan whose active tool would receive a wildcard pattern is now refused with `WILDCARD_TARGET`. The message names the way forward: run a discovery scan seeded with `example.com`, or scan the known assets that match the pattern.
- A discovery (passive) tool such as subfinder takes the pattern as its root domain: the run hands it `example.com`. A workflow takes the pattern when every step that starts the run is a discovery step. The stored scan keeps the pattern as written.
