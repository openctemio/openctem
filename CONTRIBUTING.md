# Contributing to OpenCTEM

1. Fork and branch from `develop`. Open the pull request against `develop`.
2. `make setup` once (installs dependencies and the git hooks in `.githooks/`).
3. Before pushing: `make lint test check`.
4. A change to the API contract and the web code that uses it belongs in ONE pull
   request (regenerate with `make -C api swagger && make api-types`).
5. Go code lives under `api/` (module `github.com/openctemio/openctem/api`), the
   web console under `web/`. Component guides: `api/README.md`, `web/README.md`.

Commit messages follow Conventional Commits, scoped by component where useful:
`fix(api): ...`, `feat(web): ...`, `ci: ...`.

## Changelog entries

A user-visible change adds one file `api/changelog.d/<short-slug>.md` instead of
editing `api/CHANGELOG.md`, so pull requests never conflict on the changelog.
The format and the checks are in [`api/changelog.d/README.md`](api/changelog.d/README.md).
