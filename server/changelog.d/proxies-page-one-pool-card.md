### Changed: Proxies settings page shows health at a glance and edits every pool the same way

- Settings, Scanning, Proxies opens with the organization's proxy health (proxies in use, healthy, on probation, quarantined) and re-reads it every 30 seconds while the page is visible.
- The default pool and every other pool share one card (health summary, routing strategy, sensors, Test, Edit) and one edit dialog, so the default pool can now set its strategy and description too.
- "Use proxies for scans" saves as soon as it is confirmed: turning it on lists the sensors it would hold back, turning it off warns that sensors scan from their own address. A new default pool starts off.
- Each proxy shows its connect time (p95), connection counts, last error and when its stored credentials last changed; on a phone the proxies render as cards.
