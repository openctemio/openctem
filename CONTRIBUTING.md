# Contributing to OpenCTEM

1. Fork and branch from `develop`. Open the pull request against `develop`.
2. Run `make setup` once: it downloads the Go and npm dependencies, enables the
   git hooks in `.githooks/` and generates the contract files.
3. Before pushing: `make lint test check`.
4. A change to the API contract and the web code that uses it belongs in ONE pull
   request. Regenerate the contract with `make generate` (or `make generate-docker`
   if you only have Docker).
5. Go code lives under `api/` (module `github.com/openctemio/openctem/api`), the
   web console under `web/`. Component guides: [`api/README.md`](api/README.md),
   [`web/README.md`](web/README.md); engineering docs: [`api/docs/`](api/docs/README.md).

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/), scoped by
component where useful: `fix(api): ...`, `feat(web): ...`, `docs: ...`, `ci: ...`.
Release versions are proposed from these prefixes, so pick the type carefully
(`feat` for a new capability, `fix` for a bug fix, `!` or a `BREAKING CHANGE:`
footer for a breaking change).

## Changelog entries

A user-visible change adds one file `api/changelog.d/<short-slug>.md` instead of
editing `api/CHANGELOG.md`, so pull requests never conflict on the changelog.
The format and the checks are in [`api/changelog.d/README.md`](api/changelog.d/README.md).
Internal-only changes (tests, CI, refactors, engineering docs) need no entry.

## Security issues

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).
