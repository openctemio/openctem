### Added: quick view for remediation tasks and campaigns

- Clicking a row on Fix plan > Tasks or Fix plan > Campaigns opens a details sheet over the list instead of leaving it: a side sheet on a tablet or desktop, a bottom sheet on a phone. "Open full page" goes to the task or campaign page for deep work, and ctrl/cmd-click on a name still opens the page in a new tab.
- The open sheet is in the address (`?task=<id>`, `?campaign=<id>`): the link can be shared, Back closes the sheet and a reload reopens it. The arrow keys or j and k move to the previous or next row; Esc closes the sheet and focus returns to the row.
- The task sheet shows the state, owner, deadline (with the overdue mark), progress, risk points and the first findings with links, and offers the same actions as the task page under the same permissions (Mark fixed, Put on hold or Resume, Cancel task). Its timeline and query load only when expanded. The campaign sheet shows the status, owner, due date, findings fixed and the first tasks, and the one status change the campaign allows (Start, Complete or Reopen; Cancel in the menu).
- A shared progress cell puts the count above a thin bar, centred in the row, on both lists; risk points use the plain figures of the other number columns.

Docs: none (console interaction only; the task and campaign pages and their permissions are unchanged)
