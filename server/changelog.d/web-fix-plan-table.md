### Changed: the fix plan is a ranked table that scales to many tasks

- Remediation > Fix plan shows the open tasks as one ranked table on the shared list kit instead of a card per fix: rank and task on one line (the full title on hover), findings, risk removed, the running total of risk the top tasks remove, state, owner, deadline with the "N d overdue" mark, and progress with its count. Columns fold away as the table narrows instead of wrapping.
- Search, a State and a Campaign filter, sort by risk removed (the default) or by deadline, and pages of 25, 50 or 100 with "Showing N of M". On a phone the filters, Mine, Overdue and the order are in the Filters sheet and each fix is a card with its rank, title, risk removed, state and deadline.
- The tiles (Open tasks, Overdue, My tasks) filter the table instead of opening another page.
- The running total is a share of the list's risk ("62%") only when every task of the list is on the page; otherwise it is the running total in risk points, never an estimate. Suggestions to review are no longer mixed into the plan: they have their own tab with its count.

- Docs: server/docs/architecture/remediation-tasks.md
