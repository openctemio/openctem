### Changed: the Basic | Query switch is its own control before the search field (redesign branch)

- Findings, Assets and Scans: the Basic | Query switch moves out of the search field and becomes the first
  control of the toolbar row (a two-segment switch, 32 tall, fixed width per language on a toolbar of 64rem and
  more; a code icon toggle below that, 32 px, 36 on a phone, before the Filters button). The field's end keeps only its own controls (clear; help,
  expand and run in Query mode).
- The search field holds its width when the mode switches, so switching modes no longer moves or resizes it (it
  grew from 373 to 576 px on Findings at 1440 px). On a 375 px phone the query text keeps 60 % of
  the field (53 % before).
- Docs: web/docs/findings-list.md and the query language architecture page.
