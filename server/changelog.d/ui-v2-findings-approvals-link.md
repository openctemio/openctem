### Changed: the Pending approval view opens the approvals inbox

- Under Findings in the sidebar, in pinned views and in the command palette, "Pending approval" now links to the
  approvals inbox (`/findings/approvals`), where a request is approved, rejected, reminded or cancelled. It used to
  open the findings list filtered to findings that have a request, which has none of those actions.
- The count beside it is unchanged. A link that already carries `pending_approval=true` still filters the list.

Docs: web/docs/findings-list.md
