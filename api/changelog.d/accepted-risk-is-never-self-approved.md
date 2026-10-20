### Security: a sole member can no longer approve their own accepted risk

- The sole-member self-approval (`POST /api/v1/approvals/{id}/self-approve`, authenticator code and reason) now applies to false positives only. A risk-acceptance request is refused with 403 `SELF_APPROVAL_FALSE_POSITIVE_ONLY` and stays pending until a second member of the organization approves it; risk acceptance is always four-eyes. The refusal is audited and does not spend the authenticator code.
- **Upgrade note:** a one-person organization must invite a second member (or use a false positive) to accept a risk; the shortened self-approval acceptance end no longer applies.
