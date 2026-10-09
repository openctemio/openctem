### Security: viewers no longer list stored scan credentials

- The built-in **Viewer** role (where every invitation, SSO and SCIM member
  starts) loses `scans:secret_store:read` (the list and details of stored scan
  credentials: names, kinds, descriptions, expiry) and
  `team:assignment_rules:read` (the member role never had it). Viewers lose the
  Secret store and Assignment rules pages; nothing else changes. Custom roles
  keep what their administrators gave them (migration 001420).
- The built-in roles now nest (viewer within member within administrator
  within owner), a unit test keeps them so, and a database test checks that
  the seeded grants match `permission.SystemRoles`, the list the role
  documentation is generated from.
- **Upgrade note:** a viewer who needs the secret store list gets it through a
  custom role with `scans:secret_store:read`.
