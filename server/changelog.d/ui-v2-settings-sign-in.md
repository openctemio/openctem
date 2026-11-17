### Changed: Settings > Sign-in replaces Authentication, Domains, Trusted organizations and SSO approvals (redesign branch)

- `/settings/sign-in` is one page with two tabs. Sign-in: two-factor, re-verification, email verification, the IP
  allowlist. Joining: who may join (invitations, allowed email domains, end of access, approval of new SSO members),
  personal accounts and SSO exceptions, verified domains, trusted organizations and the SSO changes an owner decides.
- Each tab has its own save bar and saves only its own settings, in the same request as before (the other tab's
  saved values go with it); unsaved changes on the other tab are kept, marked on its tab and guarded when leaving.
- `/settings/authentication`, `/settings/domains`, `/settings/trusted-organizations` and `/settings/sso-approvals`
  redirect permanently to the new page (the last three to their section on the Joining tab); a link to a setting
  (`#ip-allowlist`, `#allowed-domains`, ...) opens the tab that holds it. The settings rail shows one entry.
- Permissions (`team:update` to open, owner to save), validation, the confirmation of weaker settings, the IP lockout
  check and every API call are unchanged.
- Docs: server/docs/architecture/security-overview.md (the check links reach the new page through the redirects)
