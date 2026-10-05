### Changed: scan zones are documented as the sensor pool

- The scan-zones architecture doc states that the sensors assigned to a zone
  share its work (any of them may claim a command routed to the zone), and that
  zones (infrastructure) are kept apart from asset groups and scan targets
  (scope). No behaviour change.
