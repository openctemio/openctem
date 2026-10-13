### Added: count discovered assets in metrics on request

- Dashboards, attack-surface counts and the EASM summary and change feed count the attributed inventory by default; `include_discovered=true` on `/dashboard/*`, `/attack-surface/*`, `/easm/summary` and `/easm/changes` counts discovered assets too (RFC-054 §15.6). It changes counts only.
- The Attack surface overview has an "Include discovered assets" switch and shows how many discovered assets are passive only.
