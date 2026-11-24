### Fixed: dashboard notice and list filters hold the header still

- Dashboard: the "being built for the first time" and stale notices are back under the page header, so the header and its controls never move. When the seeded-layout note or a layout hint shows, the notice opens that note's line instead of taking a row of its own above the widgets.
- List filters: a filter keeps one width whatever value is chosen (every value reserves its width, up to 15rem), so opening a saved view no longer shrinks the search field; a long value such as "Awaiting approval" still shows whole.
- Docs: none (layout of existing pages; no behaviour, request or API change)
