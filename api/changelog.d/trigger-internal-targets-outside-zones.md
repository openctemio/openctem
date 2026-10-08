### Security: a triggered run leaves out internal addresses when the organization has no scan zones

- Scan create refuses internal addresses (private, loopback, link-local,
  unspecified, carrier-grade NAT) outside a scan zone, but a run did not check
  again: asset-group members were never validated, and a direct target saved
  while a zone covered it stayed in the scan after the zone was deleted. A
  triggered run (manual, scheduled, automation, retry) now leaves such targets
  out when the organization has no zones, counts them
  (`internal_outside_zones_target_count`, a run warning) and refuses a run left
  with nothing (`INTERNAL_TARGET_OUTSIDE_ZONES`). With zones, zone routing
  already refused uncovered targets. Platform sensors never received internal
  targets.
