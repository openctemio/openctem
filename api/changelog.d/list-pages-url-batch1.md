### Changed: more lists keep their page and filters in the URL

- The notification outbox, the notifications page, account activity and the
  admin console organizations and system logs now keep their page, page size,
  search and filters in the address. A link, a reload or Back shows the same
  page of the same list. A guard test keeps every route's main list on the
  shared list-URL hook.
