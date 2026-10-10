---
name: pr-checklist
description: What a pull request in this repository needs before it is ready - verified build, pinned lint on new code, tests, changelog fragment, complete docs, wording rules, base branch, CI green and all review threads resolved. Use before committing, pushing or opening a PR.
---

## Verify (from `api/` or `web/`)
- API: `GOWORK=off go build ./... && GOWORK=off go vet ./...`; tests of the touched packages (integration
  tests against a scratch Postgres and Redis); `make lint-new` (golangci-lint pinned to v1.64.8 with
  `--new-from-rev=origin/develop`; a global v2 binary rejects the v1 config). If lint reports findings in
  files you did not touch, your branch lags `develop`: merge it and rerun.
- Web: `npm run validate` (type-check, eslint, prettier) and `npx vitest run <touched paths>`.
- A test that fails without the change, plus a real functional check (call the endpoint, load the page).
- After merging `develop` into your branch, rerun the touched package tests: git can call a semantic
  conflict clean.

## Changelog
Never edit `api/CHANGELOG.md`. Add one file `api/changelog.d/<short-slug>.md` with
`### <Category>: <title>` and bullets (categories and format in `api/changelog.d/README.md`). Name the
migration number and any upgrade step for operators.

## Documentation, for a feature
- the RFC in `api/docs/rfcs/` with its status (H1 `# RFC-NNN: Title` and a `Status` header field), then `python3 scripts/rfc_index.py` to regenerate the `api/docs/rfcs/README.md` index (never edit its table by hand);
- an architecture doc in `api/docs/architecture/` (how it works, setup, shipped vs planned, key files),
  listed in `api/docs/README.md`;
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
