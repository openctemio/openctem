### Changed: the relationship suggestions queue follows the list pattern (redesign branch)

- A suggestion is one line: the source asset with its type, the relationship in the same words as the asset page,
  the target asset with its type, the reason and the confidence. Approve and Dismiss are buttons at the end of the
  row (the shared queue controls); changing the relationship type moved from a click on the type to the row's
  More. A reader without assets:write sees the queue without them, as before.
- The first read draws skeleton rows under the search; a failed read says what failed with Retry; a refused read
  shows the shared no-access state. Search, page and page size (25, 50 or 100) are kept in the address.
- Selection and the bulk Approve come from the shared table (no checkbox column without assets:write); on a phone
  "Select" and Scan are in one More beside Approve all, and each suggestion is a queue card.
- Every text is translated (English and Vietnamese), toasts included, and every outcome is also said to assistive
  technology. "Approve all" no longer repeats the count shown beside the queue's name; its confirmation names it.
- Docs: none (internal redesign branch)
