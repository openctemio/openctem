### Security: accepting or dismissing a high or critical exposure takes two people

- `POST /exposures/{id}/accept` and `/false-positive` (and the same routes under `/credentials`) on a high or critical item now store a pending request (202, `pending_disposition` in the response) instead of changing the state. A different approver's call for the same disposition applies it. `POST /{id}/disposition/reject` drops the request. Low and medium items are unchanged.
- The requester cannot confirm their own request. The owner can only when nobody else in the organization can approve, and that is audited Critical. Requests, approvals and rejections are audited as `exposure.disposition_*`.
- The exposures page shows the pending request with Approve and Reject for a second approver (en, vi).
- Migration `002126` adds `exposure_disposition_requests`.
