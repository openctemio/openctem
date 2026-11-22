### Fixed: the layout-breaks check for a web origin's Paths tab no longer runs out of time

- The Paths case of the layout-breaks end-to-end spec walked twelve views (five widths and languages, the endpoint sheet, two tree levels) in one test and hit its 240 second limit. Each view is now its own short test.
- The layout-breaks spec answers the page's vulnerability-data banner request itself, so a slow or never-finishing answer to it (an API image without that route) no longer holds every page in "loading" for 20 seconds per view; this was also why most other routes of the spec ran out of time on such a stack.
- Docs: none (test only; no behaviour, request or wording of the product changes)
