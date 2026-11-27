### Fixed: creating a scan no longer fails with an internal error when the organization's scan zones cover none of its targets

- `POST /scans` (and the scan dry run) answered 500 for an organization with scan zones when a target was public and no zone covered it: the zone sensor readiness check read the zone of an unzoned target. Such targets are now routed as before zones (to the organization's sensors), and the readiness check applies only to targets inside a zone.
- Docs: none (a crash fix; the documented routing of unzoned targets is unchanged)
