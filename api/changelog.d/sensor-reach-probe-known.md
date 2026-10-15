### Fixed: the platform keeps a sensor's reach probe instead of ignoring it

- Sensors since v0.20 report their built-in reach probe (tool `reach-probe`, capability `reach.probe@1`). It had no tool catalog row, so every manifest logged `ignored tools[N] "reach-probe": unknown-tool` and the platform dropped it from the sensor's inventory.
- The reach probe is a sensor service the platform requests (RFC-089 §4.3), not a scan tool tenants choose. The platform now knows it without a catalog row and keeps it, and its capability, from a sensor's heartbeat and manifest. Tools missing from the catalog are still dropped.
