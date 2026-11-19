### Added: Dismiss many findings at once from the findings list

- The findings list's bulk bar has "Dismiss" (vi "Không cần sửa") for the checked rows or for every finding the filter selects (up to 500). One dialog: false positive (default) or accept the risk until a date, one reason (the last one is preselected), and one note, required or optional as the server's preview says (optional only when you decide every finding alone and none is serious).
- Before anything changes, a live server preview says in plain words what will happen ("38 will be dismissed now. 4 need a second person: they go to approval (one request). 2 skipped: already waiting for approval."), each line expandable to its findings; it says when you will be asked to sign in again, and suggests a suppression rule when most findings come from one rule. Above 500 the dialog shows the count and offers a suppression rule instead.
- The result toast has Undo: it reopens the findings this Dismiss decided that have not changed since, and withdraws its approval request. Nothing is deleted.
- Keyboard: `D` opens Dismiss for the selection, `1`-`7` pick a reason, Ctrl/Cmd+Enter dismisses; `X` (and Shift+X for a range) is now listed in Help. The false-positive reasons are listed most common first ("Scanner was wrong", then test or example code).
- Needs the bulk dismiss API (`POST /api/v1/findings/bulk/dismiss`, `/preview`, `/{id}/undo`).

Docs: none (the redesigned console's user guide follows it; server/docs/architecture/findings-bulk-by-filter.md "Bulk dismiss" describes the API)
