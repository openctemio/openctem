### Added: decide a finding's pending request on the finding page

- An approver approves (with the sign-in confirmation) or rejects (with a reason) a pending false-positive or risk-acceptance request directly on the finding page and in the drawer, with the same dialogs and buttons as My Work. The requester still cannot decide their own request.
- The finding page shows what changed since the request ("now in CISA KEV") in the danger colour: `GET /findings/{id}/approvals` carries `changed_since_request` for pending requests, with the same rule as the review queue.
