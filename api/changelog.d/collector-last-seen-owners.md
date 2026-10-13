### Behaviour change: a trusted collector's reports are an integration source

- A report from a collector sensor of the organization at trust level `trusted` (and push ingest in effect) is recorded as source kind `integration` for attribute reconciliation, named by its tool (`ldap`, `vcenter`, …), instead of `scan`. Its owner, criticality and exposure claims are therefore used like an integration's under the organization's reconciliation policy; a person's decision still wins. An untrusted collector, or a collector of another organization, stays a scan source, so its owner claim is dropped as before.

### Added: an asset's last-seen time comes from the source's own last_seen

- A report asset's `last_seen` property (RFC 3339, `YYYY-MM-DD hh:mm:ss` UTC, or Unix seconds) is the time the asset was last seen, when it is earlier than the report's time and not before 2000; otherwise the report's time is used. The stored last-seen time never moves backwards, and an observation older than it never reactivates a stale or inactive asset (`Asset.ObserveAt`).

### Fixed: owner resolution only names active members

- The owner-resolution job matched an asset's `owner_ref` email to suspended and offboarded members too; it now names only active members of the asset's organization. An owner that matches no member stays text on the asset, and no account or invitation is created for it.
