### Changed: My Work follows the list pattern on a phone and on a desktop (redesign branch)

- One main action per screen: the open queue's Triage these is the filled button; the page's Triage (with how
  many findings wait) is an outline control on the title's line.
- The selected tab shows the queue's name and its count, once. The list's title row names the queue for screen
  readers only and shows what the list holds (one line from tablet width up, behind an info button on a
  phone), when it was updated and Refresh.
- Finding queues (Assigned to me, My team, Acceptances expiring): the "SLA due in 72 hours" toggle starts the
  toolbar and Triage these and View all end it, on one line at 390 px; "Top N of M" sits under it from tablet
  width up. No chip repeats the selected tab; the approval tabs keep "Pending".
- While the counts load, the tabs show a loading count and Triage and the queue's menu are drawn disabled, so
  the header, the tabs and the toolbar do not move when the counts arrive.
- On a phone each finding is a card: the title on the full width (two lines at most), priority and severity on
  one line, where the finding is, then the deadline and the status on one line; no mark wraps inside itself.
- No behaviour, permission, count or key changes: the tab counts still equal the list totals, the review keys
  (j, k, Enter, a, r), Approve with its sign-in step, Remind and Withdraw are unchanged.
- Docs: none (internal redesign branch; no user guide covers this layout).
