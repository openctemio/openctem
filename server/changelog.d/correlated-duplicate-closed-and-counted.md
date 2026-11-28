### Fixed: a correlated duplicate is closed and counted like any duplicate

- When finding correlation linked two detections of one issue, the duplicate got no closing time and its primary's duplicate count stayed 0. Closed-finding and time-to-fix figures left these duplicates out, and the primary did not show them among its duplicates. The link now sets the closing time and counts the duplicate on its primary; a release (by a person, or because the primary was not seen again) clears the closing time and lowers the count.
- Existing correlated duplicates keep their values until they are linked or released again; no data is rewritten.
- Docs: none (no setting or screen changes)
