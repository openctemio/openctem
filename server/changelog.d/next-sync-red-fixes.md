### Fixed: bootstrap shared reads test no longer races, and the asset tabs and the roles table stop hiding things on a phone
- The bootstrap shared-reads test recorded its calls from parallel goroutines without a lock; it now guards the recorder (a data race under `-race`).
- The asset page tabs wrap to a second line instead of scrolling out of sight on a phone (Paths tab included).
- The roles table drops the Level column below 1000 px of table width so the Permissions column is not cut at the edge.
- Docs: none (a test fix and two layout fixes, no behaviour to document)
