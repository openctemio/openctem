### Fixed: a list keeps its height and column widths when its rows arrive

- While a list loaded it drew five placeholder rows whatever it held, so a list of 25 grew by 20 rows and a list of one shrank on load. It now draws as many as the list showed last time in this browser session, else its page size, never more than fit on the screen (every list).
- The table read its frame width only after the first paint, so its column widths changed one frame after the list appeared (cells moved sideways). The width is read before the first paint now.
- Docs: web/docs/ui-style-contract.md (loading rows)
