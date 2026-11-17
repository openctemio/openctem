### Changed: the findings list says which state it is in and what to do next

- First run shows "No findings yet" alone, with no toolbar, chips or count: Run a scan, Import results and Connect a tool, each shown only to someone who may use it.
- A refused read says the viewer cannot read findings here, hides Add finding and Triage, and offers one action, Go to the dashboard.
- A no-match offers Clear filters and "Search all states" (was "Search all statuses").
- When a refresh fails, the rows stay and the footer says how old they are with a refresh button; the same note appears once the rows are older than 5 minutes.
- A list whose total is not known says "Could not count" with Retry beside the view name, the pager shows the rows on screen without a total, and Last page is disabled with its reason (also for a capped total, where the button was missing).
- A failed load shows no count beside the view name.
- An empty table disables the header's select-all checkbox.
- Docs: web/docs/findings-list.md, web/docs/ui/shared-kit.md
