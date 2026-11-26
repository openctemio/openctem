### Security: role changes need a recent sign-in

- Creating, editing or deleting a role, applying a template update to a role, and granting roles (to one user, a replaced role set, or many users at once) now need step-up, the same critical rule as API keys, SCIM tokens and the other organization-control changes: outside the window the API answers `403 STEP_UP_REQUIRED` and the web console asks the person to confirm their identity, then retries. Taking a role away from a user stays one click. Every one of these writes is audited.
- Docs: server/docs/architecture/step-up-reauth.md
