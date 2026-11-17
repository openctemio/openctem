### Changed: Needs attention asset queues follow the list pattern (redesign branch)

- The five asset queues (Validate primary assets, Decide monitoring, No owner, Criticality not set, Not scanned in
  30 days) keep their page, page size and sort in the address, so a queue position can be linked to and survives a
  reload; riskiest first stays the order at rest.
- The first read draws skeleton rows under the queue's header and no count; a later read keeps the rows on screen
  with the refresh bar. A failed read says what failed in the table with Retry; a refused read shows the access
  message instead of the queue.
- On a phone, "Select" is in the queue's own More beside "Open in the inventory", not in a one-item menu of the
  table.
- Docs: none (internal redesign branch)
