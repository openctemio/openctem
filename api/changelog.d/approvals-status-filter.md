### Fixed: the approvals list filters by status and counts within the data scope

- `GET /api/v1/approvals` takes `status` (pending, approved, rejected,
  canceled, expired; without it every status is listed) with `page` and
  `per_page`, and returns `status_counts`. It used to return pending
  approvals only, so the Approved, Rejected and Canceled tabs of
  Findings > Approvals were always empty.
- For a restricted member the list, `total` and `status_counts` are filtered
  in the query to approvals whose finding is in their data scope (the total
  used to count every pending approval of the organization).
- The Approvals page reads each tab from the server, pages through it, and
  shows Cancel only on the caller's own pending requests (the server refuses
  anyone else).
