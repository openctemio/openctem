### Changed: the scan runs list follows the shared list pattern (redesign branch)

- Rows are one line: the scan (a link to the scan page; a click on the row still opens the run), the status with
  what the targets held back and the run's message cut to the column (whole in the hover text and in the run's
  sheet), the intensity in a column of its own, the tasks, findings, duration, start and who started it. The scan
  stays in view while the table scrolls sideways; Intensity and Triggered by step aside on a narrow table and stay
  under Display > Columns.
- Title row: the view's name (runs started by people, by the system, or all runs), the count once, Refresh and
  Export CSV. On a phone the two actions are in one More.
- Toolbar: Add filter (key `f`), then Origin and Status as two selects of a fixed width, the Status values with
  their counts. Kind is set from Add filter and shows as a removable chip under the toolbar; the scan a "View all
  runs" link named is a chip too. The list has no search field: the run list API takes field filters only.
- The list still refreshes itself while runs are live. Rows under the pointer keep their places through a refresh;
  another page, filter or sort keeps the current rows on screen until the new ones arrive.
- The line that sums up the platform's own runs moved under the list, so the header never moves when a filter hides it.
- An empty list says whether no run has started yet or no run matches, with Clear filters. A refused read shows
  the no-access notice.
- Phone: the Scans header keeps its title and the two create actions (Quick scan, New scan) as named icon buttons in
  one row, on Scans and Runs; the section description shows from 768 px. On Runs the list comes first and the
  status tiles follow it; the same counts are beside each Status value in the filter sheet, which holds every filter.
- No API change: the same reads, filters, sorts and export.
- Docs: none (layout of an existing list; filters, actions and permissions are unchanged)
