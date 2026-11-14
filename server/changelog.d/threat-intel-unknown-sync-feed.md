### Fixed: the Threat intelligence "Sync status" tab no longer ends in a page error

- The tab threw "Prioritization Error" as soon as the API listed a feed the console had no display entry for (the `vulnfeed` catalog feed next to EPSS and KEV). It now shows that feed as "Vulnerability feed", and any other new feed under its id. The Prioritization error page no longer says "failed to load data" for a page that broke while drawing, and asks for a reload when a deploy replaced the code under an open tab.
- Docs: none (console fix, no behaviour change)
