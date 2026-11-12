### Added: names only an internal sensor can resolve are scanned through that sensor's zone

- A company network that answers names differently inside and outside (split-horizon DNS) no longer has its internal-only names refused as "does not resolve in DNS from the platform". The platform keeps, per sensor, what each name resolved to in the reports of that sensor's commands, and zone routing uses that answer: a name a sensor resolves to a private address of its own scan zone routes to that zone.
- A name is refused as unresolved only when neither the platform nor any sensor of the organization resolves it. A sensor's private answer is never a scope grant: the address must be inside the sensor's zone and not excluded or rejected, otherwise the name is refused (`vantage_out_of_scope`). Shared and platform sensors never record or receive such names.
- Migration 20261107025253 adds the `name_resolutions` table (empty at first; it fills as sensors report).
