### Added: scan freeze windows in the console

- Settings, Policies, Scan freeze windows lists, creates, edits and deletes the organization-wide windows (one-off or weekly, in a chosen time zone); each scan zone has its own windows from the zone list (Freeze windows), and a zone held by a window shows Frozen.
- A banner on Scans and on Scan zones names the active windows and when they end.
- Run now during a window: members holding `scans:freeze:override` are asked whether to start the scan anyway (audited); others are told why it did not start.
