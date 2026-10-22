### Security: finding decisions that close risk need a fresh sign-in

- Approving a false-positive or accepted-risk request (`POST /api/v1/approvals/{id}/approve`), approving a group exception (`POST /api/v1/approvals/batches/{id}/approve`), approving a severity change, deleting a finding (`DELETE /api/v1/findings/{id}`) and a bulk move to a closed status (`POST /api/v1/findings/bulk/status`) now answer 403 `STEP_UP_REQUIRED` unless the session signed in or stepped up within the step-up window. Reject and cancel are unchanged. The web console asks for the re-authentication and retries.
- **Upgrade note:** API keys and automation that approve, delete or bulk-close findings now get 403 `STEP_UP_UNAVAILABLE`; those decisions need a signed-in user session.
