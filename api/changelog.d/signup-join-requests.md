### Added: onboarding offers invitations and the organization of a verified domain; join requests

- An account without an organization gets its pending invitations, the organization that claims its
  verified email domain (only when that organization is discoverable and allows joining) and whether
  it may create one: `POST /api/v1/auth/onboarding/options`, `POST /api/v1/auth/onboarding/accept`
  (refresh-token authenticated). Offers carry opaque references bound to the account; no
  organization id or slug is shown. Taking an offer accepts the invitation, joins at once as the
  domain's role (`auto`) or creates a join request (`approval`).
- Organizations decide requests in their own inbox: `GET /api/v1/organization/join-requests`,
  `POST .../{id}/approve` (viewer or member only) and `.../reject`. One pending request per person
  and organization, 5 a day per person, 30-day expiry, purged 30 days after decision. Audited.
- Migration 002521 adds `organization_join_requests`.
