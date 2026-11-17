### Changed: the Vulnerabilities list follows the shared list pattern (redesign branch)

- Rows are one line: the CVE id (a link to the vulnerability page, kept in view while the table scrolls sideways),
  the title with its first aliases, the exploitation signals (Known exploited and an emerging threat always show first;
  further ones show while they fit and are counted otherwise, with their words in the tooltip), priority, severity with the CVSS score, EPSS with its 30-day line, the asset count with the
  internet-facing count, the fix and the remediation state. Last seen, Remediation and Fix step aside on a narrow table
  and stay under Display > Columns.
- The title row names the view (the open saved view, else "All vulnerabilities") and states the count once. A changed
  view shows Modified, Save view and Reset. Refresh and Export CSV are in the same row; on a narrow row and on a phone
  they fold into More, which starts with Select.
- Toolbar: search, Add filter (key `f`), then Findings and Sort as two selects of a fixed width (under 1024 px Sort
  moves into Add filter, so the toolbar keeps one row). Every other filter is
  set from Add filter and shows as a removable chip in one row under the toolbar, with Clear filters. The docked filter
  panel is gone; on a phone the Filters button joined to the search field opens every filter in a sheet.
- Selection uses the table's own checkbox column and bulk bar: the first two actions the user may take are buttons,
  the others are under More (Create task, Accept risk, Retest, Export, in that order, with the same confirmations). A
  user with none of them gets no checkboxes.
- An empty list says whether there is nothing yet or nothing matches (with Clear filters); a failed read with rows on
  screen keeps the rows and says how old they are; a refused read shows the no-access notice.
- No API change: the same reads, filters, sorts, saved views and bulk endpoints.
- Docs: none (layout of an existing list; filters, actions and permissions are unchanged; `server/docs/architecture/vulnerability-page.md` describes the new layout)
