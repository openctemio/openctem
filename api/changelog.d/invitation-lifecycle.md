### Added: invitation preview, resend limits and revoked invitations kept

- `POST /api/v1/organization/invitations/preview` tells the inviter, before sending, whether the organization's invitation policy allows the address (with a reason code), whether the person is outside the organization or uses a personal address, whether the roles need the inviter's re-authentication and the member's two-factor, whether an end of access is required, and whether they are already a member or invited. It reveals nothing about other organizations.
- The pending invitations list shows whether the invitee is outside the organization, whether two-factor will be required, the end of access, the last send and the number of resends.
- Migration `invitation_lifecycle` adds `revoked_at`, `last_sent_at`, `resend_count`, `invitee_kind` and `privileged` to `tenant_invitations`.

### Security: invitation quotas cannot be bypassed and invitations are single use

- Cancelling or declining an invitation keeps it as revoked instead of deleting it, so the plan's daily invitation limit counts what was sent; revoked rows are purged after 30 days.
- A resend waits at least 10 minutes and an invitation is sent again at most 5 times; one person sends at most 50 invitations an hour (429).
- Seats are checked when an invitation is created, counting members and pending invitations, not only at acceptance.
- Accepting an invitation updates only one that is not yet accepted or revoked.
