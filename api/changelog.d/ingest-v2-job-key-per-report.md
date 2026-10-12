### Fixed: two sensors that use the same report id no longer block each other

- Protocol v2/v3 segment jobs were keyed by the report id the sensor chose, under an idempotency index that is per organization, not per sensor. If a second sensor of the organization used the same report id with the same bytes, its segments and commit failed with `500` until the report expired. That happened by accident, or deliberately when a compromised sensor copied a sibling's id. Jobs are now keyed by the stored report's own id, which is unique across sensors.
