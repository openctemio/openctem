### Fixed: an emerging-threat alert lists its affected assets per host, under honest group names

- The alert page showed likely matches under "Confirmed affected" and counted them there. It now has three
  groups, each shown only when it has a row: Confirmed affected, Likely affected, Possibly affected (version
  unknown).
- A host that serves several ports has one service asset per port (`http://host`, `https://host`). These are
  different assets and stay so, but the page listed them as separate rows that read as duplicates. They now
  share one row per host: the host as the title, each service as a link to its own asset, internet-facing if
  any service is, the highest criticality, the distinct products and versions, and the finding and task links
  of every service. A group's count is its number of rows.
- `GET /api/v1/emerging-threats/{id}` adds `asset_groups` (tier, hosts, services); `assets` is unchanged.
  The list, the drawer, messages and the stored counters count hosts the same way (see "an emerging-threat
  alert counts hosts everywhere").
- On a phone the affected assets are cards under the same group headers instead of a table cut at the
  screen edge.
- Docs: server/docs/architecture/emerging-threat-alerts.md
