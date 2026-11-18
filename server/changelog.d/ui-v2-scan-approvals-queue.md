### Changed: Scan approvals follow the queue list pattern (redesign branch)

- A title row with the number of requests and Refresh, a Status filter with every status (awaiting approval
  by default, or all requests), and a table with the scan, its status, the run marks (emergency, intensity),
  who asked, the rule, the approvals left, the decide-by date (overdue in red) and when it was asked.
- Pages of 25, 50 or 100 replace Load more; the count is the whole queue.
- Approve and Reject stay on the row; Details (targets, what runs, what changed since the last approval),
  Approve my own scan, Remind and Withdraw are in its More menu. Withdraw now asks first.
- Every decision is also said in a status region; a refused read says so instead of offering Retry.
- Docs: none (no guide describes this layout).
