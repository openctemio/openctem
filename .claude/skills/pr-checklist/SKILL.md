---
name: pr-checklist
description: What a pull request in this repository needs before it is ready - verified build, pinned lint on new code, tests, changelog fragment, complete docs, wording rules, base branch, CI green and all review threads resolved. Use before committing, pushing or opening a PR.
---

## Before every push: `make precheck` (repo root)
- Run `make hooks` once per clone. Then `make precheck` before each push: a branch not pushed yet is rebased
  onto the branch its PR targets; a pushed branch is merged with it only when the two conflict (i18n catalogs
  merge key by key), since a clean "merge develop" commit only re-runs CI (the merge queue tests every PR on
  top of the newest develop). It stops on a conflict it cannot resolve so you resolve it locally, warns about
  other open PRs touching the same files, then runs what CI's lint and static gates run (API: gofmt, vet,
  staticcheck, golangci-lint on new code; web: prettier, eslint, tsc, separator gate, sorted catalogs). The
  pre-push hook refuses an unpushed branch that is behind its base and a pushed branch that conflicts with it.
- Several agents work at once: run it right before pushing, not only when the branch was created.

## Verify (from `server/` or `web/`)
- API: `GOWORK=off go build ./... && GOWORK=off go vet ./...`; tests of the touched packages (integration
  tests against a scratch Postgres and Redis); `make lint-new` (golangci-lint pinned to v2.14.0 with
  `--new-from-rev=origin/develop`; use the Makefile's pin, not a global binary). If lint reports findings in
  files you did not touch, your branch lags `develop`: merge it and rerun.
- Web: `npm run validate` (type-check, eslint, prettier) and `npx vitest run <touched paths>`.
- A page redesigned to its design board: its entry in `web/e2e/design/manifest.ts` and the design gate green
  at both widths and both themes (`npx playwright test -c playwright.design.config.ts`, `web/docs/ui/design-gate.md`).
- A test that fails without the change, plus a real functional check (call the endpoint, load the page).
- After merging `develop` into your branch, rerun the touched package tests: git can call a semantic
  conflict clean.

## Changelog
Never edit `server/CHANGELOG.md`. Add one file `server/changelog.d/<short-slug>.md` with
`### <Category>: <title>` and bullets (categories and format in `server/changelog.d/README.md`). Name the
migration number and any upgrade step for operators.

## Documentation, for a feature
- the RFC in `server/docs/rfcs/` with its status (H1 `# RFC-NNN: Title` and a `Status` header field), then `python3 scripts/rfc_index.py` to regenerate the `server/docs/rfcs/README.md` index (never edit its table by hand);
- an architecture doc in `server/docs/architecture/` (how it works, setup, shipped vs planned, key files),
  listed in `server/docs/README.md`;
- the authorization matrix and permission tables when gates or roles change.
Mark clearly what is shipped and what is only designed.

## Wording
- Describe the design on its own terms. Do not name or compare with other products in code, docs, commit
  messages or PR text; integrations and tools the code actually runs, and standards, are fine to name.
- No RFC or phase tags in code comments; link the design once at the top of the file.
- No AI attribution lines (the `commit-msg` hook rejects them) and no `@mentions`; wrap package names
  such as `` `@types/node` `` in backticks in titles.
- Examples use `example.com` and documentation IP ranges, never real targets.

## Open and finish
- Base branch `develop`; small PRs, one concern each.
- CI green, every review thread resolved (bots too): fix at the root, reply, resolve.
- Never commit generated contract files (`make generate` produces them) or merge-conflict markers.
