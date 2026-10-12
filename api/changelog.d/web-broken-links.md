### Fixed: email verification links and dead links in the console

- The email verification link pointed at a page that did not exist. It now
  opens `/verify-email` (token in the URL fragment, never sent to a server),
  which verifies the address; the welcome email links to `/login` instead of
  `/auth/login`, and the dead `/support` links are gone from the emails.
- Documentation links in the console come from one module
  (`web/src/lib/docs-links.ts`) and point at docs.openctem.io: the CI/CD
  guides and the scanner content help now open the docs site.
- A web test fails when a literal in-app link points at a route that does not
  exist (removed the dead `/unauthorized`, `/settings/appearance`,
  `/settings/display`, `/help-center` and `/dashboard/*` targets).
