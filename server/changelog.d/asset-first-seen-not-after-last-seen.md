### Fixed: a new asset is first seen when its source saw it

- An asset created from a sensor report stored the arrival time as first seen and the report's own (earlier) observation time as last seen, so the asset said it was first seen one or two seconds after it was last seen. A new asset is now first seen at the observation time, and first seen is never later than last seen. Stored assets keep their first seen; the store never rewrites it.
- Docs: none needed (no behaviour a reader configures; timestamps only).
