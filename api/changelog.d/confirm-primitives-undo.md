### Changed: Undo toasts last 10 seconds; typed confirmations ignore phone capitalisation; console purge asks for the name

- Reversible changes (finding status and assignee, archiving and marking assets not ours, EASM decisions) offer Undo for 10 seconds through one shared helper, which sends the inverse command once.
- The typed-confirmation field turns off autocapitalise, so a phone keyboard no longer breaks the exact match, and Enter in it never fires the action.
- The platform console's "Delete now" for an organization also asks for the organization's name.
- A web test fails when a component calls a destructive endpoint (delete, revoke, purge, reset, rotate, disable and similar) without a confirmation dialog or Undo, unless the file is listed with a reason.
