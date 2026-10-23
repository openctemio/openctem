### Changed: findings quick views in the sidebar replace the metric strip and the state tabs

- The sidebar lists seven built-in views under Findings with live counts: Active, Needs triage, My queue, SLA breached, Pending approval, Accepted · expiring and Closed. Each opens the findings list with the view's own filter, and the count is the total that list shows.
- The seven metric cards and the Open / Fixed / Dispositioned / All tabs are removed from the list. The first row names the current view and its total; Awaiting verification is a button there while fixes wait for a verifier.
- The list accepts `state=closed`, `pending_approval=true` and `acceptance_expires_at_lte` in the page URL.
- A cold load of the findings page stays within 5 API requests: the source catalog now loads when the Source filter is opened, and Refresh sends each request once instead of twice.
