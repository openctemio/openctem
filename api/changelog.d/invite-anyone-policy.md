### Behaviour change: invite anyone, to any role, unless the organization restricts invitations

- People outside the organization (personal addresses, other companies' domains, unverified work domains) may now be invited to any role but owner. They no longer join as viewers only, and their access no longer has to end in 90 days (RFC-095 §4, amending RFC-058).
- New security settings (owner, step-up, audited): `invitees` (`any` by default, `verified_domains`, `allow_list`) and `external_access_end_required` (off by default; on restores the mandatory end of access, 90 days by default and 365 at most, for outside people no organization manages). An organization with `allowed_domains` set reads as `allow_list`.
- Inviting or giving an outside person a role above member (admin, full data access, or member, team, role, API key or settings administration) needs the inviter's recent re-authentication, and that member must prove a second factor every time a token is minted for the organization. A trust with their home organization still caps them at its `max_role`; full data access never reaches them through a team.
- Outside members may create API keys unless an active trust forbids it, never beyond their end of access.
- Invitation refusals carry codes: `INVITEE_NOT_ON_VERIFIED_DOMAIN`, `INVITEE_DOMAIN_NOT_ALLOWED`, `INVITATION_NO_LONGER_VALID`, `PERSONAL_ACCOUNTS_BLOCKED`.

### Security: an invitation stops working when its inviter can no longer grant it

- Accepting an invitation now re-checks, as the inviter, that they are still an active owner or administrator who could grant every role in it (the admin role only from the owner). An invitation from someone who left, was suspended or demoted is refused and grants nothing; before, its roles were stored regardless.
- `POST /api/v1/invitations/accept-with-refresh` now runs the same acceptance as `/invitations/accept` (audit included) and applies the organization's SSO, two-factor and personal-account policies before it mints a token.
