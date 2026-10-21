### Fixed: exposure chains compute in linear time

- The exposure-chain builder ran one search per public asset on every request: about 4 s at 5,000 assets, 70 s at 20,000 and 156 s at 50,000. It now makes a single pass from all public assets (about 33 ms at 50,000 assets), so large tenants can open the page.
- Chains skip relationships that point at deleted assets.

### Removed: `reachable_from_entry_points` on exposure chains

- The exposure-chain response no longer includes `reachable_from_entry_points`, and the page no longer shows the "entry points" counter on a chain. The count measured the size of the external footprint, not risk. Each chain still names its entry point.
