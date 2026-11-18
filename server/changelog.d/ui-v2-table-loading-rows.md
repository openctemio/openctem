### Fixed: a list keeps its height and column widths when its rows arrive

- While a list loaded it always drew five placeholder rows, so a list of 25 grew by 20 rows and a list of one shrank on load. It now draws as many as the list showed last time in this browser session, never more than fit on the screen; a list not shown before still draws five (every list).
- The table read its frame width only after the first paint, so its column widths changed one frame after the list appeared (cells moved sideways). The width is read before the first paint now.
- Docs: web/docs/ui-style-contract.md (loading rows)
