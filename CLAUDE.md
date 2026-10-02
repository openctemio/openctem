# OpenCTEM monorepo — guidance for Claude

This repository is `api/` (Go) + `web/` (Next.js). Each has its own, detailed
CLAUDE.md — read the one for the directory you are changing:

- [`api/CLAUDE.md`](api/CLAUDE.md) — Go API: TDD, DDD layout, golangci-lint, migrations.
- [`web/CLAUDE.md`](web/CLAUDE.md) — web console: patterns, style guide, i18n.
  Skills for web work live in `web/.claude/skills/` (picked up when working under `web/`).

## Rules that span both

- Branches: PRs target `develop`; `main` is the release branch. Merge with a
  merge commit or squash, never "rebase and merge" for branches containing merges.
- One PR may change both sides. If you change a handler's request/response, run
  `make -C api swagger` then `make api-types` and commit both: CI fails if
  `web/src/lib/api/generated/api.types.ts` does not match `api/api/openapi/swagger.yaml`.
- Go: run tools from `api/` with `GOWORK=off`; module path is
  `github.com/openctemio/openctem/api`.
- Release: one `vX.Y.Z` tag on `main` publishes both images.
- No AI attribution lines in commits or PRs (enforced by `.githooks/commit-msg`).
