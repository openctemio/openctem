### Added: the console manages the two-factor floor and organization mail servers

- Console Settings > Two-factor sets the lowest two-factor requirement of every organization (no floor, owners and administrators, everyone) and the days current and new members get to set it up. It shows where the value comes from (`AUTH_MFA_FLOOR` or the console) and recommends a floor on an upgraded install still on none. Lowering the floor asks for confirmation.
- Console Settings > E-mail gains Organization mail servers: whether an organization's own mail server sends its organization mail (never, only from a verified domain, always). Account security mail always uses the platform server.
- Both used existing API routes that had no page (`/api/v1/admin/settings/auth-mfa`, `/api/v1/admin/settings/email-relay`): super admin, fresh step-up, a reason, critical audit and every administrator told. The Configuration overview links both settings to their pages.
