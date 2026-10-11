### Added: GitHub App installations for CI checks and pull request comments

- A deployment can register the OpenCTEM GitHub App (`GITHUB_APP_ID`,
  `GITHUB_APP_SLUG`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`,
  `GITHUB_APP_PRIVATE_KEY_FILE`, `GITHUB_APP_WEBHOOK_SECRET`; steps in
  `docs/how-to/github-app.md`). Permissions: checks and pull requests write,
  metadata read.
- An organization binds its installation (`GET /api/v1/ci/scm-apps`,
  `POST /api/v1/ci/scm-apps/github/install-url`,
  `POST /api/v1/ci/scm-apps/github/installations`,
  `DELETE /api/v1/ci/scm-apps/installations/{id}`; `scans:ci:write` to change).
  Binding needs the install state the console issued to the person for that
  organization (15 minutes) and the person's own GitHub authorization reaching
  the installation; one installation belongs to one organization. Audited
  (`scm_app.installed`, `scm_app.removed`).
- `POST /api/v1/webhooks/incoming/github-app` takes installation events,
  verified with the app's webhook secret before anything is read: a deleted or
  suspended installation stops being used at once (`scm_app.status_changed`).
- Posting the check and comments follows in the next change (RFC-077 phase C).
