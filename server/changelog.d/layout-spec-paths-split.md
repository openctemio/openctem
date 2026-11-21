### Fixed: the layout-breaks check for a web origin's Paths tab no longer runs out of time

- The Paths case of the layout-breaks end-to-end spec walked twelve views (five widths and languages, the endpoint sheet, two tree levels) in one test and hit its 240 second limit. Each view is now its own short test.
- The page's vulnerability-data banner request is answered by the test itself, so a slow or never-finishing answer to it no longer holds the page in "loading" for 20 seconds per view.
- Docs: none (test only; no behaviour, request or wording of the product changes)
