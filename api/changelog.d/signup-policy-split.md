### Added: the sign-up policy decides account sign-up and organization creation separately

- Console > System > Sign-up has two choices: who may create an account (`accounts`: closed, domain,
  open) and who may create an organization (`mode`: admin_only, self_service; self_service needs
  open accounts). Each is limited by `SIGNUP_MODE`: `domain` allows domain sign-up but never open
  sign-up or organizations. The hosted service can keep sign-up open while pausing organization
  creation. `PUT /api/v1/admin/settings/signup` takes `accounts`; `GET` also reports `accounts`,
  `max_accounts` and `effective_accounts`; `GET /auth/providers` reports `signup_accounts`.
- The admission rule gains two outcomes: `domain_account` (the account joins its verified domain's
  organization, never creates one) and `sso_required` (an address on a domain whose organization
  requires its SSO is refused for password and social sign-up, nothing written). Domain policies
  that produce them follow in the next change.
- A stored policy keeps its meaning: `self_service` reads as open account sign-up, `admin_only` as
  closed.
