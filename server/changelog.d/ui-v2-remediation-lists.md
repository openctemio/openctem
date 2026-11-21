### Changed: the remediation Tasks and Campaigns lists follow the shared list pattern (redesign branch)

- Tasks: columns in the order Task, Owner, State, Progress, Risk points, Deadline. Owner, Risk points and
  Progress step aside on a narrow table; the task name and its state stay. Several owners read
  "Network team, Sam Rivera". The Show filter, the search, the sort, the Table or Board switch and "From query"
  sit in one toolbar in both layouts; on a phone the Show filter moves into the Filters sheet beside the search.
- Campaigns: columns in the order Campaign, Status, Owner, Tasks, Findings closed, Due. "New campaign" moved from
  the page title to the end of the toolbar, as on every list.
- Both lists show the shared states: a first-use empty state with its next step, "No tasks match these filters"
  (or campaigns) with Clear filters, a loading table and a retryable error that keeps the rows already loaded.
- On a phone each task or campaign is one card: the name with its state on the first line, the owner, then the
  progress and the deadline.
- Permissions are unchanged: creating a task from a query still needs remediation write and findings read, and
  "New campaign" needs remediation write.
- Docs: none (the redesigned console is documented when it ships)
