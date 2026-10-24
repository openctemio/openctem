### Fixed: finding assignee shows its name in the list and the drawer
- The findings list now returns `assigned_to_user` (id, name, email) for each row, resolved in one tenant-scoped lookup per page. Only active members of the caller's organization resolve; any other assignee id keeps `assigned_to` and carries no profile.
- The finding drawer no longer reads "Unassigned" (or shows a raw id) for an assigned finding whose name has not loaded: it shows the name once the record arrives, "Assigned" until then.
