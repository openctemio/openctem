### Changed: Ready to close follows the queue list pattern (redesign branch)

- Each tab has a title row with the number of findings and Refresh; the table keeps that row while it loads,
  fails (Retry) or is empty, and a refused read says so instead of offering Retry.
- The finding, its severity, the critical-close mark, the asset, how the close is proven (method and Held
  mark, tool, when it was scanned, the scan) are columns of their own; on a phone each finding is a card with
  the same facts and its decision.
- Confirm close and Keep open are named with their finding for screen readers; rows are selected with the
  shared table selection (ranges, the x key, Select on a phone) for one decision on many.
- Every decision and its result is also said in a status region; Recently auto-closed does the same for
  Reopen: not fixed. The tab count shows "…" while it loads.
