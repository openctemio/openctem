### Behaviour change: discovered assets join the inventory at once; scope still decides what is scanned

- What a scan or CT logs find outside every permanent scope entry is now stored as `discovered` and listed in the inventory at once, instead of waiting outside it in the review queue (RFC-054 §15).
- A discovered asset gets passive checks only unless an active scope entry covers it: scans refuse it with `no_entry`. Exclusions, rejections and the deny list still win.
- New scope setting `review_before_inventory` (default off) keeps the old review gate for organizations that want it.
- Dashboards, attack-surface counts and the CT watch list count only attributed assets (new asset filter `attributed`); the asset filter `approved` now includes `discovered`.
- Upgrade: migration `inventory_first_discovered` moves automatic `needs_review` records to `discovered` (a person's decisions are untouched); down restores them.
