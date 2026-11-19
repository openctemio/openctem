### Changed: settings rail groups follow the task (redesign branch)

- "Access & security" is split into "People and access" (members, teams, roles, service accounts, API keys, AI
  assistants, directory sync) and "Sign-in and oversight" (sign-in, security overview, audit log, support access).
- Approvals is a group of its own; Scan approval stays in Scanning. The tool, sensor and detection-content pages
  move from Scanning to a "Tools and sensors" group.
- Group and page names say "and", not "&". The rail starts with "Back to app" and "All settings".
- SIEM is called "Event forwarding" in the rail, on its page and in the integrations overview.
- URLs do not change; no redirects are needed. No API change.

Docs: web/CLAUDE.md (the Settings navigation section lists the new groups); no public guide names the old groups
