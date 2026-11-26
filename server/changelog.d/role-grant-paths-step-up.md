### Security: every path that grants a role needs a recent sign-in

- Binding a role to a team, changing a team's access or upgrading its preset, sending an invitation, creating a user, and changing a member's team role now need step-up (critical tier), like the role routes. Before, these needed it only when they granted an administrator or a privileged role. Outside the window the API answers `403 STEP_UP_REQUIRED`, and the web console asks the person to confirm their identity, then retries.
- Docs: server/docs/architecture/step-up-reauth.md
