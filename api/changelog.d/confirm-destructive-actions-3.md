### Fixed: settings confirmations name what they delete and are translated (part 3)

- Confirmations for API keys, service accounts and their keys, SCIM tokens, secret-store
  credentials, SIEM, ticketing, SCM and notification integrations, the notification outbox,
  finding templates, SLA policies, roles, module resets, sessions, MCP connections and
  applications, trusted organizations, verified domains, identity providers, SAML, report
  schedules, SSO change approvals and organization deletion now name the object, state the
  consequence and are translated (English and Vietnamese).
- Revoking or deleting an API key, deleting a service account or one of its keys, revoking a SCIM
  token and deleting a secret-store credential now ask the user to type its name. A bulk delete of
  ten or more finding templates asks for the count.
- Delete-role and the report-schedule delete use the shared confirmation (Cancel focused, no
  double submit) instead of their own dialogs.
