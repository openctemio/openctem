### Fixed: documentation and in-app links from the API

- The sensor setup checks linked to `docs.openctem.io/sensor/troubleshooting`,
  a page that does not exist: they now open the matching entry of the setup
  check reference on `/sensors/troubleshooting/`.
- In-app notifications for scope changes opened the removed `/scope-config`
  page (now `/scope`), CI break-glass alerts opened the removed
  `/settings/scanning/ci` page (now CI/CD, Trust and gate), and member
  lifecycle notices go to `/settings/members` directly.
- CI checks every docs.openctem.io and GitHub file link in code against the
  docs site and the repositories (job "Docs links" in `docs-check.yml`).
