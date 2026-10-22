### Fixed: the findings bulk bar follows permissions, SLA sort, safer bulk writes

- The findings list offers row selection and the bulk bar only when the user can run a bulk action: assigning needs `findings:bulk_update` and `findings:assign`, status changes need `findings:bulk_update` and `findings:status` (the API already required both); analysts without them no longer get 403s from the bar.
- The Due / SLA column sorts by deadline (most overdue first).
- A bulk write cannot be sent twice by a double click, and a failed bulk resolve keeps its note and dialog open.
- The drawer's assignee control is disabled without `findings:assign`.
