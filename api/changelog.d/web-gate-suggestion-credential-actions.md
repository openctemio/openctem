### Fixed: review actions show only to people who may use them

- Assets > Suggestions shows Scan, Approve all, Approve, Dismiss, the bulk
  approve bar, row selection and the relationship type editor only with
  `assets:write`, the permission the API checks on those routes. Readers see
  the queue.
- Credentials: "Mark resolved" shows only with the credentials write
  permission the API checks on `POST /credentials/{id}/resolve`.
