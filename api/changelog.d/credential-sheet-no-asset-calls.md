### Fixed: credential leak sheet no longer shows "Asset not found"
- The credential leak detail sheet asked per-asset endpoints (scope and scanning, owners, timeline, relations) with a credential id, which is not an asset id, so they answered 404 and the sheet showed an error. It now asks none of them.
- "Scope and scanning" shows "does not apply" for a type the asset type registry lists no scan target for, instead of loading.
- The Risk card names open findings the severity breakdown does not place, and a credential leak counts its one finding in its own severity.
