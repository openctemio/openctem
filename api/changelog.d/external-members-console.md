### Added: console views for external members, trusted organizations and personal accounts

- **Organization switcher:**
  - marks organizations where you are an external member and says when your access there ends;
  - disables an organization you cannot open, with the reason;
  - offers a search above seven organizations.
  - `GET /users/me/tenants` returns `kind`, `access_expires_at` and `blocked_reason` for each membership.
- **Members:**
  - Internal / External filter (`?kind=`);
  - badges: External, Personal, Unmanaged, Lapsed domain, SSO exception, end of access;
  - "Change end of access" for external members.
- **Invitations:** an end of access for people outside the organization, and a warning when the address looks like an existing member's.
- **Settings › Trusted organizations:** request, approve, change and end trusts with partner organizations.
- **Settings › Authentication:**
  - the personal-accounts policy;
  - while SSO is enforced, the SSO exception list.
- **Platform administrator console:** each verified SSO domain of an organization shows and changes how SSO treats newcomers (role, or not admitted).
