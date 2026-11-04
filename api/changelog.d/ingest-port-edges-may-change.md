### Security: port scan edges follow the report's authority

- A port scan's `exposes` (address to port) and `resolves_to` (host name to address) edges are added only when the report may change their source asset: an unsolicited report, an address outside a bound command's targets, or an upload whose actor may not change the asset no longer adds them (RFC-040 §5.3).
- Port `exposes` edges record when they were last seen, so a rescan refreshes them.
