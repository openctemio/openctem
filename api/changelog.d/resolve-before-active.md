### Behaviour change: active stages skip names that have not resolved for a week

- Port scans, HTTP probes, templates and other active stages now take a host name only while the platform holds evidence from the last 7 days that it resolves (its DNS, HTTP, TLS or port observations). Older names are left out (`not_resolving`) and their DNS is checked again through the automatic enrichment; names the platform knows nothing about are still handed to the sensor. Passive stages (DNS resolution, discovery) still take them (RFC-088 decision A5).
- A single-scanner run records how many names it left out (`not_resolving_target_count`, a warning) and is refused with `NO_RESOLVING_TARGETS` when nothing is left.

### Security: the wildcard-DNS filter is on by default, decided by the platform

- Every dnsx job that does not set `wildcard_filter` gets `true` from the platform, so a name that resolves only through a wildcard record is never reported and never reaches an active stage (RFC-088 decision A4). dnsx steps now validate `record_types` and `wildcard_filter` when saved.
