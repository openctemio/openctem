### Security: more sensitive actions ask for re-authentication

- Making someone an administrator or an owner (role assignment, bulk assignment, member role change, adding a member, an invitation or a created user with the admin role), renaming the organization's slug, reading or rotating the Jira and GitHub webhook secrets, and changing the attachment storage configuration now need a recent sign-in or step-up (10 minutes), like API key creation already did. Outside the window the API answers `403 STEP_UP_REQUIRED` and the web console shows its re-authentication dialog, then retries.
- Granting an ordinary role, re-saving an existing administrator's roles, renaming the organization without changing its slug, and grants applied for someone else (an accepted invitation, SCIM, SSO provisioning) are unchanged.
- `oct_` API keys cannot perform these actions (`STEP_UP_UNAVAILABLE`).
