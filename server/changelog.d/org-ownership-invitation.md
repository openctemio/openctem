### Added: a platform administrator can create an organization for someone who already has an account

- Console > Organizations > New organization with the email of an existing account no longer refuses
  ("This person already has an account..."). The organization is created with no owner and no member,
  and that account gets an ownership invitation (7 days, at most 5 sends, 10 minutes apart). The person
  accepts or declines in the web app (My account, or the page the email links to); accepting needs a
  recent re-authentication and a verified email address. Nobody becomes an owner without accepting.
- The console shows "Waiting for owner to accept" on the organization, with Send again, Change invitee
  and Cancel invitation on its Users tab. A new email works as before.
- New routes: `GET /api/v1/me/ownership-invitations`, `POST /api/v1/me/ownership-invitations/{id}/accept`
  (step-up), `POST .../decline`, `POST /api/v1/admin/tenants/{tenantId}/owner-invitation/resend`,
  `DELETE /api/v1/admin/tenants/{tenantId}/owner-invitation` (ops_admin+, step-up).
- Migration `20261102094502_organization_owner_invitations` (new table only).
- Design: `docs/architecture/organization-ownership-invitations.md`.
