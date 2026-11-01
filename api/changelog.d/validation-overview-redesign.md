### Changed: the Validation overview shows what is waiting for you

- Validation › Overview has one "Waiting for you" list: fixes waiting for validation, pentest retests due, closes ready for a verifier and open campaigns, each with the one action that empties it. Queues with nothing in them leave the list; with nothing waiting, the block names the places where validation work starts.
- One strip above it: P0/P1 validation coverage (the closed P0/P1 figure the CTEM cycle's close gate uses, with its two classes, and a header link to how it is measured), findings validated in the last 30 days, findings whose latest re-check still reproduces them, and findings reopened in the last 30 days. Each tile opens the findings list it counts.
- The page no longer repeats the sidebar as cards and no longer loads 200 pentest findings for a recent-activity list. A module the organization switched off leaves the page without a request to its API; owners and admins see one line naming the switched-off validation modules, with a link to Settings › Modules.
- The overview and the Retest queue header are translated (English and Vietnamese).
