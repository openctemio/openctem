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

## Checks on a pull request

The required checks are listed in
[`api/docs/development/ci-cd.md`](api/docs/development/ci-cd.md). One more check,
**Dependency Review**, runs on every pull request but is not required: it fails
when a Go module, npm package or GitHub Action that the pull request adds or
upgrades has a known high or critical advisory. Treat a red result as a blocker
unless a maintainer agrees otherwise.

## Security-sensitive changes

A pull request that changes authentication or authorization, tenant isolation,
cryptography or signing, the sensor protocol, the scope gate, web session or
header code, upload/download handlers, the SSRF guard, CI workflows or
deployment defaults (the full list is
[`.github/security-paths.yml`](.github/security-paths.yml)) is labelled
`security-sensitive` and gets an automated security review comment. The
required `security-gate` check passes once a maintainer has reviewed it and
added the `security-ack` label, and no HIGH finding is open. Every other pull
request passes the check at once.

- Contributors and automation never add `security-ack` themselves.
- New commits that change a sensitive file remove the ack; the maintainer acks
  again after reviewing them.
- A reviewed false positive of a diff rule is waived on its line with
  `security-review: allow <RULE-ID> <reason>`.
- Emergency override: an administrator may bypass the check; the bypass is in
  the organization audit log and is followed by a written reason on the pull
  request.

Details: [Security gate](api/docs/development/ci-cd.md#security-gate).

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

## Contributor License Agreement

Every outside contribution is accepted under the OpenCTEM Contributor License
Agreement (CLA). It keeps your copyright with you and grants the project a
license that lets it offer OpenCTEM under its open source license and under
other terms (for example a commercial license). A summary is in
[CLA.md](CLA.md); the full texts are the
[Individual CLA](https://docs.openctem.io/legal/cla/) and the
[Corporate CLA](https://docs.openctem.io/legal/cla-corporate/).

### How to sign

1. Make sure the e-mail address of your commits is
   [added to your GitHub account](https://github.com/settings/emails). The
   check can only match commits that are linked to a GitHub account.
2. Open your pull request. If a commit author has not accepted the CLA yet,
   the `cla` check fails and comments on the pull request.
3. Read the agreement and post this comment on the pull request:

   ```text
   I have read the CLA Document and I hereby sign the CLA
   ```

   The check re-runs and passes. You sign once; the signature covers every
   repository of the `openctemio` organization and your earlier
   contributions. Post `recheck` to run the check again.
4. If you contribute as part of your job and your employer has rights in your
   work, your employer signs the [Corporate CLA](CLA-CORPORATE.md) as well.

The maintainer and the dependency bots are on the check's allowlist. A
maintainer who opens a pull request with someone else's commits makes sure
those authors have signed; the check also runs then for every commit linked
to another GitHub account.

### What is recorded

Your acceptance is recorded in a private repository that only the maintainer
can read: your GitHub username and numeric account id, the id and time of
your signing comment, and the repository and pull request where you signed.
No e-mail address is stored. The signing comment itself stays public on the
pull request. The record is kept for as long as the project distributes your
contribution, because it is the evidence of the license. To see or correct
your record, or to ask for its removal, write to info@openctem.io; anything
not needed as evidence of the license is removed.
