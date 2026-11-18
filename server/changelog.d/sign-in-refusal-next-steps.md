### Fixed: a refresh refused by an organization names the reason and its next step

- When an organization stops admitting a signed-in session (single sign-on or its identity provider's second-factor proof now required, a verified address or a work account needed, the organization suspended), the console opens the account space with the reason and its one next step instead of retrying or showing a bare sign-in page. The session stays for the person's other organizations.
- Docs: server/docs/architecture/session-refresh.md (refresh refusals are classified by web/src/lib/auth/refresh-failure.ts)
