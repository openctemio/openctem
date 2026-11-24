### Fixed: dashboard notice and list filters hold the header still

- Dashboard: the "being built for the first time" and stale notices are back under the page header, so the header and its controls never move. When the seeded-layout note or a layout hint shows, the notice opens that note's line instead of taking a row of its own above the widgets.
- Findings: the Practice and State chips keep one width again, so opening a saved view (the chip reads "Set by the view", cut to the chip's width and whole in its hint) no longer shrinks the search field. Other filters still show a long value such as "Awaiting approval" whole.
- Docs: none (layout of existing pages; no behaviour, request or API change)
