### Security: the sole member of an organization can approve their own finding request, with an authenticator code

- Before, an organization with one person could not mark anything a false
  positive or accept any risk (nobody else could approve). Now
  `POST /api/v1/approvals/{id}/self-approve` (`findings:approve`) lets the
  requester approve their own pending request only when they are an owner and
  the organization has exactly one active person (checked at decision time;
  suspended members and service accounts do not count), with a fresh code
  from their authenticator app (a used code cannot be replayed) and a reason.
  Inviting a second member closes the path at once.
- An accepted risk approved this way ends sooner: at most 7 days for P0 or a
  known exploited vulnerability, 45 days for P1, 90 days otherwise (a longer
  end asked for is brought forward; `end_shortened` in the response).
- The request is marked `self_approved` (API, timeline), audited
  `finding_approval.self_approved` at high severity, refusals audited
  `finding_approval.self_approval_refused`, the organization's channels get a
  security alert, and the backup contact is emailed when configured.
- New settings section `finding_approvals` with `backup_contact_email`
  (`GET|PUT /api/v1/organization/settings/finding-approvals`; the change needs
  `settings:write` and a recent re-authentication, is audited
  `finding_approval.settings_changed` with before/after, and the approvers are
  told in-app).
- The approvals list returns `self_approval_available` for the viewer.
- Migration `002446` (`finding_approval_self_approved`): a boolean with a
  constant default and a nullable text column.
