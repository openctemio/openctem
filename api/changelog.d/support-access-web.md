### Added: support access in the web app and the admin console

- Settings › Support access (owners and admins): how support access works, a
  "Grant access" dialog for owners (support administrator's email, findings
  and/or assets, 1 to 72 hours, reason, optional case reference; confirmed
  with a re-authentication), the active access with Revoke, and the history
  with status, session count and last access. A link opens the audit log
  searched for support events.
- Every member sees a banner while platform support can read the
  organization's data (who, which data, until when, case), stronger while a
  support session is open, with a link to the page for owners and admins.
- Admin console › Customers › Support access: the grants that name the
  signed-in administrator and a read-only support session opened from one,
  framed with its end time, with Overview, Findings and Assets (only the
  granted scopes), search, filters, pages and a detail drawer. When the
  access is revoked, expires or ends elsewhere, the session view closes and
  says so. The server checks and audits every read; the UI only reflects it.
