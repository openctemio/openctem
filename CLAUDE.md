# OpenCTEM monorepo — guidance for Claude

This repository is `api/` (Go) + `web/` (Next.js). Each has its own, detailed
CLAUDE.md — read the one for the directory you are changing:

- [`api/CLAUDE.md`](api/CLAUDE.md) — Go API: TDD, DDD layout, golangci-lint, migrations.
- [`web/CLAUDE.md`](web/CLAUDE.md) — web console: patterns, style guide, i18n.
  Skills for web work live in `web/.claude/skills/` (picked up when working under `web/`).

Procedures live in skills under `.claude/skills/` (loaded when relevant):
`pr-checklist` (before any commit or PR), `api-route` (routes, permissions,
modules), `migration` (database migrations), `web-change` (web console).

## Rules that span both

- Branches: PRs target `develop`; `main` is the release branch. Merge with a
  merge commit or squash, never "rebase and merge" for branches containing merges.
- One PR may change both sides. The contract files (the OpenAPI spec, the web
  API types, the web route permission map, the route manifest) are generated,
  NOT committed: run `make generate` after pulling or after changing a
  handler, a route or its gate (`make generate-docker` if Go or Node is
  missing). Web CI type-checks the web against the fresh contract and posts the
  contract diff (breaking changes, route gate changes) on the pull request.
- Go: run tools from `api/` with `GOWORK=off`; module path is
  `github.com/openctemio/openctem/api`.
- Release: one `vX.Y.Z` tag on `main` publishes all six images from one commit
  (`openctem-api`, `openctem-web`, all-in-one `openctem`, `migrations`, `seed`,
  `admin-cli`). `ui/v*` tags are imported history from `openctemio/ui`; never create one.
- Cite old web PRs as `openctemio/ui#NNN`: a bare `#NNN` means this repository.
- CI, required checks and images: `api/docs/development/ci-cd.md`; repo map:
  `api/docs/development/repositories.md`.
- No AI attribution lines in commits or PRs (enforced by `.githooks/commit-msg`).
- Changelog: never edit `api/CHANGELOG.md` for a change; add one file
  `api/changelog.d/<short-slug>.md` (format in `api/changelog.d/README.md`).
  API CI refuses an entry under Unreleased and any committed conflict marker.
- Security first: every change states its threat model and its authorization
  and tenant-isolation impact, with cross-tenant and out-of-scope negative
  tests. The tenant comes from the authenticated principal, never the request.
- Committed text (code, docs, RFCs, commits, PR text) describes our design on
  its own terms: no names of or comparisons with other products. Tools and
  integrations the code runs, and standards, are named where used.
- No RFC or phase tags in code comments; link the design once at the file top.
- A feature is documented when its RFC, the `api/docs/rfcs/README.md` index and
  an architecture doc in `api/docs/architecture/` are up to date.
