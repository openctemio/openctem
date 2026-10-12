### Changed: RFC-055 records how the legacy capability vocabulary is retired

- RFC-055 §10.1 records the OC5 decision.
- Custom capabilities stay as tenant labels, each optionally mapped to one ctis taxonomy capability id, which then drives routing. Tenant rows are never deleted.
- Only the legacy matching columns and the old-sensor name fallback are dropped, one release train after the command-logs sensor release is live everywhere.
