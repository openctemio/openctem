### Added: scope entries name their approvers; reminders; an owner without another approver can approve

- A scope entry waiting for approval now says how many approvals it still needs and who can give them (owners, administrators and members with the scope approval permission, never the requester). Names are shown to people who may see the organization's members; everyone else sees the count.
- The approvers are told in-app, by email and on the organization's notification channels. "Remind approvers" (`POST /api/v1/scope/targets/{id}/remind`) sends the request again, at most once an hour per entry.
- When nobody else can approve an entry (an organization with a single owner), the owner who requested it can approve it with a reason and a code from their authenticator app (`POST /api/v1/scope/targets/{id}/self-approve`). It is audited at high severity and every administrator is told. Nothing is approved automatically.
- Migration `001600` adds `scope_targets.approval_reminded_at` and the `self_approved` and `reason` columns of `scope_target_approvals`.
