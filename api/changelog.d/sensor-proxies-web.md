### Added: Settings, Scanning, Proxies page and a per-sensor Network path
- Paste a list of proxies (`scheme://user:pass@host:port#label`) to send the scan traffic of your own sensors through them; credentials are write-only and show as `••••` after saving.
- Each proxy shows its state (healthy, probation, quarantined), score, last error and last success; disable a proxy or reset its health from the table.
- More pools for network segments, and a Network path select on the sensor page: inherit the organization default, go direct, or use a pool.
- New permissions `sensors:egress:read`, `sensors:egress:write` and `sensors:egress:delete` gate the page.
