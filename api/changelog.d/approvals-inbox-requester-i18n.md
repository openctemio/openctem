### Changed: the approvals inbox names the requester, is translated and is in the main menu

- `GET /api/v1/approvals` returns `requested_by_name` for each request: the requester's name when they are a current member of the organization (looked up in the caller's organization only); a former member and an AI triage or VEX request have no name.
- The approvals inbox has a Requester column ("You", the member's name, "Former member", or the platform actor), and Approve and Reject are disabled on the viewer's own request with the reason shown (the server still refuses a self-approval).
- Every text on the inbox and the request dialog is translated (English and Vietnamese).
- "Approvals" is a main menu entry under Findings; for approvers it shows the number of pending requests in their data scope.
- The requester of a pending request can remind its approvers from the inbox (at most once an hour; uses `POST /api/v1/approvals/{id}/remind`). The inbox shows the request's decide-by date, and the acceptance end is labelled as such.
