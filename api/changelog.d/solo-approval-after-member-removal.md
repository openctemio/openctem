### Security: no sole-member self-approval within 7 days of a member being suspended or removed

- The owner of an organization with one active person can approve their own
  finding request only when no member was suspended, offboarded, deleted or
  had their membership expire in the last 7 days (memberships and the audit
  log are read at decision time). Otherwise the request is refused with
  `SELF_APPROVAL_AFTER_MEMBER_REMOVAL`, naming when it becomes possible, and
  the refusal is audited. A stolen owner session can no longer remove the
  other approver and approve alone.
