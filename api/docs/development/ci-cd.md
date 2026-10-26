# CI/CD

CI for the `openctemio/openctem` monorepo (`api/` + `web/`). All workflows live
in the repository root's [`.github/workflows/`](../../../.github/workflows/);
`api/` and `web/` have none of their own. The workflow files are the source of
truth: this page describes them as of the merge-queue routing (#730, 2026-10-02).

## Workflows

| Workflow (file) | Triggers | What it does | Gate check |
|-----------------|----------|--------------|------------|
| API CI (`api-ci.yml`) | PR / push to `develop`; merge queue | `API static checks` (one job: migration safety, SQL schema drift, security gates, OpenAPI contract, gateway routing, go vet, staticcheck, golangci-lint), tests against Postgres + Redis, least-privilege suite, PostgreSQL 18 migrations, release binaries, Docker build; see [Tiers](#tiers) | **API CI OK** |
| Web CI (`web-ci.yml`) | PR / push to `develop`; merge queue | `API contract` (generates the contract files; for an API change compares them with the base and reports the difference), `API contract report` (the pull request comment), `Web checks` (type-check against the generated contract, ESLint, Prettier, palette drift, separators, and the copy linter `web/scripts/check-copy.mjs` on added or changed English strings: no marketing words, "successfully", exclamation marks, em dash asides or Title Case labels; `node scripts/check-copy.mjs --all` lists the existing strings to clean up) and `Web tests` (Vitest in three parallel shards); `next build` (push only) | **Web CI OK** |
| CodeQL (`codeql.yml`) | PR / push; merge queue; weekly (Mon 00:00 UTC) | One matrix over the languages: Go (built inside `api/`) and JavaScript/TypeScript (`web/`), one category per language. Go runs `security-and-quality` with `go/log-injection` replaced by `.github/codeql/go-queries/LogInjectionUnstructured.ql` (`openctem/go/log-injection`): the same sources, sinks and sanitizers, minus the key-value attributes of `log/slog` calls, which slog's text and JSON handlers escape (pinned by `api/pkg/logger/forging_test.go`); the message argument and every other logger stay checked, and `logger.SanitizeValue`, `SanitizeText` and `SanitizeError` are recognised sanitizers. PR and merge queue: only the changed language(s). Push to `develop`/`main` and weekly: both, so each branch keeps a fresh baseline per category | **CodeQL OK** |
| Web E2E (`web-e2e.yml`) | PR (with `run-e2e`, a changed suite, or the full tier) / push to `develop`; merge queue | Builds the API, web and admin images once, then runs the Playwright suite (`web/e2e`) in 4 shards, each against its own stack (Postgres, Redis, migrations, seeded tenant). The merge queue runs it whenever the queued PR changed `web/`, `api/` or a shared file, so a spec made stale by a layout change fails in the queue, not on `develop`. `Merge reports and list flaky tests` is for people and never fails the gate | **E2E OK** |
| Web visual regression (`web-visual.yml`) | PR with the `run-visual` label; nightly on `develop`; on demand | Screenshots of the key pages (dashboard, findings, assets, scans, remediation tasks, My Work, settings) at 1440 light and dark and 390 light against `web/e2e/visual/__screenshots__` (`playwright.visual.config.ts`, 2% pixel tolerance, volatile values masked). A missing baseline is written, not failed; `workflow_dispatch` with `update` takes new baselines and uploads them as the `visual-baselines` artifact to commit. Diffs are uploaded on failure | none (not required) |
| All-in-one CI (`allinone-ci.yml`) | Push to `develop`; merge queue; a PR only when it changes `.github/workflows|scripts|actions` (check "All-in-one (PR build)", not required; other PRs get `All-in-one OK` from `pr-hygiene.yml`) | Builds `openctem-api`, `openctem-web` and the all-in-one `openctem` image exactly as a release does, smoke-tests them (arch, ELF, executes) and runs the all-in-one in both gateway modes against Postgres + Redis. Nothing is pushed. Merge queue and pushes only (see [Tiers](#tiers)). | **All-in-one OK** |
| Repository Security (`repo-security.yml`) | PR / push; merge queue; weekly | Betterleaks (root `.betterleaks.toml`, `.gitleaksignore`): a PR or queued group scans only its own commits (`base..head`); a push to `develop`/`main` and the weekly run scan the full history. Customer identifiers: fixed strings from the `CUSTOMER_DENYLIST` repository secret (never committed; empty = skipped with a notice) and the live LAN range outside tests, over every tracked file, printing only file:line. Commit emails: a PR or queued group fails when one of its commits has an address from the `COMMIT_EMAIL_DENYLIST` repository secret (case-insensitive fixed strings such as a domain; never committed; empty = skipped with a notice) as author, committer or `Co-authored-by` trailer, printing only the commit and the field; outside contributors are covered by the CLA check. **Workflow Lint**: actionlint and zizmor (pinned; suppressions are per line with a reason, inline or in `.github/zizmor.yml`, never per file) over the workflows, action pins, and the self-tests of the CI scripts (change routing, CodeQL alert gate, security gate and its CODEOWNERS mirror), plus the check that `api/` and `web/` depend on no sensor module or SDK. **Dependency Review** (PR only) | **Secret Scanning**, **Workflow Lint** |
| PR hygiene (`pr-hygiene.yml`): Docs check | PR / push to `main`, `develop`; merge queue | Also in this workflow: the release-note labels job (below) and, on a PR, the `All-in-one OK` report (the build itself runs in the merge queue). **Docs check** job: `scripts/docs_check.py` (Markdown is English, has no private addresses or internal host names, relative links and anchors resolve), the RFC index check, then `scripts/check_docs_links.py` checks every `docs.openctem.io` link in code (page and `#anchor`, against a checkout of `openctemio/docs` `main`) and every `github.com/openctemio/<repo>/blob\|tree/<ref>/<path>#anchor` link (this repository from the checkout, others fetched shallowly); tests are skipped, `docs-links: ignore` skips a line. Locally: `python3 scripts/check_docs_links.py --docs ../docs --fetch-other .` | **Docs check** |
| API Security (`api-security.yml`) | PR / push (`paths:` api side, see below); weekly | One job for govulncheck + Trivy (fs) + license check; Semgrep; Snyk (only if `vars.ENABLE_SNYK == 'true'`), license check, image scan (only for a PR into `main` / weekly) | — |
| Web Security (`web-security.yml`) | PR / push (`paths:` web side, see below); weekly | One job for npm audit + Trivy (fs) + ESLint security rules; Snyk (opt-in as above), image scan (only for a PR into `main` / weekly) | — |
| API Fuzz (`api-fuzz.yml`) | Nightly (03:17 UTC), manual | 10 minutes of `FuzzStrictCTIS` (the protocol-v2 results decoder); uploads a crasher artifact on failure | — |
| API Authorization Matrix (`api-authz-matrix.yml`) | Nightly (02:11 UTC), manual | `make -C api authz-matrix`: a scratch stack (Postgres, Redis, migrations, the API from this commit), two seeded organizations, every route as every principal with own and other-organization ids, plus the role-management scenarios ([Authorization matrix suite](../architecture/authorization-matrix.md#authorization-matrix-suite)); the JSON report is an artifact (7 days) | — |
| Ingest load (`api-ingest-load.yml`) | Nightly (02:41 UTC), manual | Fresh Postgres 17, all migrations, then `TestIngestLoad` (`INGEST_LOAD=1`): 50 concurrent CI uploads × 1,000 findings through the real accept path, queue and 4 workers; an urgent report behind 500 bulk jobs; 20 uploads of the same findings to one repository. A missed target fails the job; the results table is the run summary (RFC-122 §6e) | — |
| Docker Publish (`docker-publish.yml`) | Tag `v*`, manual | Builds, smoke-tests, publishes, signs and SBOMs every image (see [Images](#images)); on a production release also the offline image bundle | — |
| Release (`release.yml`) | Tag `v*`; dispatch on a tag | GitHub Release with the release archives (via Release archives), their SBOMs, the signed `checksums-sha256.txt`, build provenance, and the image pull lines | — |
| Release archives (`release-dist.yml`) | Called by Release; PRs touching its inputs (`paths:`) | Builds the archives with `.github/scripts/release/build-dist.sh`; on a PR builds linux/amd64 only and runs `smoke-dist.sh` (versions, `-check-config` of the example settings, `systemd-analyze verify`/`security`, gateway Caddyfile, web/console health, the image kit's Dockerfiles), publishing nothing | — |
| API PostgreSQL Compatibility (`api-pg-compat.yml`) | Nightly 02:17 UTC (default branch), push to `develop` touching migrations, the role script or `internal/infra/postgres/`, a PR that changes the workflow, manual | The least-privilege method (roles bootstrapped by a superuser, every migration applied as the migrator, the suite run as the app role) on PostgreSQL **16 and 18**, the three `pkgs` shards each; it fails if the server is not the major under test and if a DB test skipped. Not required (see [Supported PostgreSQL](#supported-postgresql)) | — |
| Tool Pin Freshness (`tool-pins.yml`) | Mondays 02:00 UTC (from `main`), manual | Compares the inline tool pins in `.github/tool-pins.tsv` with the newest stable releases and opens, updates or closes one issue "Tool pins to bump" (see [Tool pin freshness](#tool-pin-freshness)); `issues: write` only, no pull request | — |
| API Upgrade Test (`api-upgrade-test.yml`) | Nightly 03:30 UTC (default branch), push to `release/**`, a PR into `main`, manual (optionally from an older release) | Builds the previous release's database, loads representative rows, applies this tree's migrations and asserts the result (see [Upgrade test](#upgrade-test)). Not required; a failure on a release branch means do not merge the release PR | — |
| Release-note labels job of `pr-hygiene.yml` | PR (opened, pushed, reopened); same-repository PRs only | Adds the `notes:*` labels by the files and diffs the PR changes (see [Release-note labels](#release-note-labels)); not required, never fails a PR | — |
| Release Train (`release-train.yml`) | Manual (a maintainer presses Run) | Proposes the version from conventional commits, picks the newest develop commit with every required check green, builds `release/vX.Y.Z` (with one commit setting `versions.yaml` `platform.release` to `vX.Y.Z`), opens and queues the release PR (see [Releases](#releases)) | — |
| Release Publish (`release-publish.yml`) | A `release/v*` PR merged into `main`; manual | Tags `vX.Y.Z` (only if `main`'s tree is the release branch's and its `versions.yaml` says `vX.Y.Z`), starts Docker Publish + Release, opens the develop and helm-charts follow-up PRs, closes the train issue | — |
| API CI `Detect API changes` step "Changelog fragments" | PR, merge queue, push (also docs-only changes) | `api/scripts/changelog.py check`: fragment format, no entry under Unreleased in `api/CHANGELOG.md`, no committed merge-conflict marker | — |
| Release Reminder (`release-reminder.yml`) | Mondays 01:00 UTC (train weeks only); manual | Opens/updates the issue "Release train vX.Y.Z" with the proposal and changelog preview | — |
| Security Gate (`security-gate.yml`) | PR (opened, pushed, reopened; labelled and retargeted through `security-gate-label.yml`); merge queue | Classifies the PR against `.github/security-paths.yml` and reviews its diff; a security-sensitive PR passes only with the `security-ack` label and no open HIGH (see [Security gate](#security-gate)). The gate's unit tests and the CODEOWNERS mirror run in **Workflow Lint** (they run PR code; the gate job never does) | **security-gate** |
| Security Gate Label (`security-gate-label.yml`) | PR (`security-ack` added or removed, retargeted) | Re-runs the head's `security-gate` run, which the pinned gate workflow does not start on labels; decides nothing itself | |
| CLA (`cla.yml`) | PR to any branch (opened, pushed, reopened); a PR comment that signs or says `recheck`; merge queue (passes) | Checks that every commit author has accepted the [Contributor License Agreement](../../../CONTRIBUTING.md#contributor-license-agreement); records new signatures in the private `openctemio/cla-signatures`. Runs in the base context and never checks out pull request code. In the merge queue it passes at once, so it can be required on pull requests. **CLA scope test** (`cla-test.yml`, when the workflow changes) tests who must sign against recorded commit lists | **cla** |
| Release Tooling (`release-tooling.yml`) | PR / push touching `versions.yaml`, the release scripts or a versioned default | **Release scripts** (shellcheck + shell tests) and **Version consistency** (`sync-versions.sh --check`; on `release/vX.Y.Z` and on `main` right after it merges, `--release vX.Y.Z`: `platform.release` must be that version) | — |
| CI image mirror (`ci-image-mirror.yml`) | Push to `develop` changing the list or the scripts; daily (04:23 UTC); manual | Copies the third-party images CI pulls, and the digest-pinned base images of the sensor's Dockerfiles, to `ghcr.io/openctemio/mirror` (see [CI image mirror](#ci-image-mirror)) | — |

Scheduled runs (weekly security, nightly fuzz) run from the default branch, `main`.

### Required checks

Branch protection on `main` and `develop` requires exactly these eight checks.
Merges go through the GitHub merge queue (see [Merge queue](#merge-queue)); the
strict "branch must be up to date" rule is off, because the queue itself tests
each PR on top of the current base:

- `API CI OK`
- `Web CI OK`
- `E2E OK`
- `CodeQL OK`
- `All-in-one OK`
- `Secret Scanning`
- `Workflow Lint`
- `security-gate`

`E2E OK` is required because the queue is the only place where a PR's specs
meet every layout change merged before it: a spec a PR never touched can go
stale against another PR's page change, and without the check that PR still
merged and turned `develop` red.

The five `… OK` checks are aggregator jobs (`if: always()`): they pass when every
job they depend on passed **or was skipped**, and fail when any failed or was
cancelled. The other jobs are not required individually; they reach the merge
through their aggregator. API Security and Web Security are not required.

Code-scanning result checks (CodeQL, Semgrep, Trivy alerts) are separate from
these workflow gates.

### Security gate

One human maintainer reviews every change, and most pull requests are opened by
automation under that maintainer's account, so GitHub's "required approvals"
cannot work (an author cannot approve their own pull request). The
`security-gate` check replaces them for the changes where a second look matters
most, and stays out of the way for everything else.

**What counts as security-sensitive.** A pull request that changes a file
matched by [`.github/security-paths.yml`](../../../.github/security-paths.yml):
authentication, sessions and authorization gates (middleware, auth routes and
handlers, the permission model), tenant isolation and data scope (and the
`tenantsql`/`getbyid`/`routeperm` guards), encryption, keys and signatures, the
sensor protocol (transports, mTLS, ALPN routing in the gateway, pairing), the
scope gate, web session/CSRF/proxy/header code, upload and download handlers,
the SSRF guard (`pkg/httpsec`), CI workflows and release scripts, Dockerfiles and
deployment defaults. Tests and the `tenantsql` table list count only when the
change removes lines (adding a test strengthens a guard, removing one weakens
it). A pull request is also sensitive when its added lines hit a content rule:
a migration that changes row-level security, database grants or role
permissions, or a security default in `api/internal/config/config.go`.
`.github/CODEOWNERS` mirrors the list (a generated block; the self-test fails
when they differ). Measured on the 150 pull requests merged before the gate
existed: about 40% would have been sensitive, in a period dominated by scope,
signer and sensor-protocol work.

**What the gate does** (`.github/scripts/security_gate.py`, Python standard
library only):

1. Reads the pull request's changed files through the API and classifies them.
   A non-sensitive pull request passes at once, with no comment.
2. Reviews the added lines with high-precision rules. HIGH (blocks): TLS
   verification disabled, JWT parsed unverified, `pull_request_target`,
   `write-all` tokens, an action not pinned to a SHA, event text interpolated
   into a workflow, raw HTML sinks or `eval` in the web app, row-level security
   disabled or grants to `PUBLIC` in a migration. MEDIUM (reported): outbound
   HTTP outside `pkg/httpsec`, raw client-IP headers, `os/exec` in the API,
   SQL built with `Sprintf`, wildcard CORS, privileged containers.
3. Lists new code-scanning alerts: open on the pull request's analysis
   (CodeQL, Semgrep, Trivy) and not open on the base branch. A new **high or
   critical** alert blocks. It also lists the results of the security checks on
   the head commit (govulncheck, Semgrep, Trivy, npm audit, secret scanning,
   golangci-lint with gosec).
4. Labels the pull request `security-sensitive` and posts one comment (updated
   in place) with the reasons, the findings and what is needed.
5. Passes when the pull request carries `security-ack` added by a user listed
   under `ackers` in the path list, and no HIGH finding or new high/critical
   alert is open.

**Acknowledging (the maintainer's one click).** Read the gate comment and the
diff of the listed files, then add the **`security-ack`** label. The gate
runs again and turns green; queue the pull request as usual. The pinned gate
workflow (see "Pinning the required check" below) starts only on opened,
pushed and reopened, so the small `security-gate-label.yml` workflow re-runs
the head's gate run when `security-ack` is added or removed or the pull request
is retargeted: it waits for that run to finish and calls the re-run API (a
re-run keeps the run's event and pinned workflow version, and the gate reads
the labels again). It decides nothing: a missing re-run leaves the check red
(re-run it by hand; fork pull requests always need that, their token is
read-only), an extra one evaluates the same records again. In the merge queue
the gate runs again (`merge_group`), finds the pull request from the queue
branch name and reads its labels, the push log and code-scanning alerts
through the API; nothing depends on a run started by the label.

- The ack covers the commit it was added on, and later commits that leave the
  security-sensitive lines alone. The gate never stores or reads a decision in
  its comment (any workflow on any branch of the repository writes as the same
  `github-actions[bot]`, so a comment proves nothing). It reads only records
  GitHub writes itself:
  1. the newest `labeled` issue event for `security-ack`: who added it and
     when (the actor must be listed under `ackers`);
  2. the commit it was added on: the tip of the pull request's head branch at
     the label's time, from the branch's push log (`GET
     /repos/{head repository}/activity`, every push, force push, creation and
     deletion of the branch with GitHub's own timestamp and new tip). Commit
     author and committer dates are never read (the pusher writes them), and
     neither are workflow runs or check suites (a pull request's workflows
     decide which runs exist, and a workflow token can create check suites).
     A pull request or its workflows can add to the push log only by really
     moving the branch, which the log then records. If the branch moved 60
     seconds or less before the label, the page the acker read may still have
     shown the previous head: the gate cannot tell and fails closed (add the
     label again). The whole log is read and ordered by time; a log longer
     than 3000 entries, an API error or no entry before the label fails
     closed. The gate comment shows this commit next to the current head, so
     the acker can confirm what the label covers.
  The issue-event list must be complete: its newest `security-ack` event must
  be the `labeled` one (the label is on the pull request), and a list of 3000
  events or more fails the check, since it may be cut off.
  On the label event itself, or when that commit is still the head, the ack
  stands. Otherwise the ack is carried over from an older commit, and the gate
  fetches both commits (history and trees; blobs on demand) and recomputes
  from git a digest of the security-sensitive lines of each, against the
  current base: every added and removed line (no context, no line numbers) of
  each file that makes the pull request sensitive, from the diff against the
  merge base. Equal digests keep the ack, so merging the base branch in,
  rebasing, or pushing changes to other files keeps it, while changing a
  sensitive line, adding a sensitive file or resolving a conflict inside one
  drops it. In the merge queue an ack that no longer covers the head blocks
  the group (nothing is written there).
- No carried-over ack, whatever the digest, when:
  - the pull request changes `.github/workflows/**`, `.github/actions/**`,
    `.github/security-paths.yml` or `.github/scripts/security_gate.py` (on
    `pull_request` events GitHub runs the pull request's own workflow files,
    which could act on the pull request): the ack covers only the exact commit
    it was added on, so every push needs a new ack. Its own workflows cannot
    move the acknowledged commit: they decide which runs exist, but the push
    log, not a run, names that commit. Until a ruleset requires the gate
    workflow (below; read from GitHub's rules API for the base branch) the
    gate comment says that the pull request's own workflow files decide what
    the check runs (they could replace the gate outright, so failing closed
    there would add no protection and would only block every workflow change
    in the merge queue);
  - the base branch changed after the label (a `base_ref_changed` issue event
    after the `labeled` one, also without new commits: a retargeted stacked
    pull request now carries its parent's changes);
  - the push log cannot name the commit (see above): the gate cannot tell
    which commit was acknowledged.
- Migration renumbering keeps the ack: a migration counts in the digest by its
  name without the version number, in version order, so the merge queue moving
  a pull request's migrations above `develop` (same names, same order, same
  content) changes nothing, while editing or reordering them does. The gate
  does **not** check where the renumbered migrations now run relative to the
  ones `develop` added meanwhile: a migration that depends on (or conflicts
  with) a newer `develop` migration keeps the ack. That ordering is the
  migration lint's and the reviewer's job.
- Renaming a security-sensitive file after the ack always needs a new ack,
  even when its content is unchanged: the digest is computed from git without
  rename detection, so a rename reads as one file removed and another added.
  (Only a migration's version prefix is exempt, as above.)
- Base merges that change the diff keep the ack too. When `develop` changed
  the same sensitive file, the pull request's own `+`/`-` lines can shift (a
  removed line now reads differently, a hunk merged into `develop` by a stacked
  parent disappears) and the digest differs although nobody touched the
  change. Then the gate keeps the ack only if the acknowledged commit is an
  ancestor of the new head (a rebase or force-push is acked again) and every
  sensitive file of the pull request is the same blob in the new head as in a
  clean `git merge-tree` of the acknowledged commit with the newest `develop`
  commit the new head contains (migrations matched by name and order). A
  sensitive change in any non-merge commit, or a conflict resolved inside a
  sensitive file of a merge commit, fails this; plain files may change freely.
  Every git or API error counts as "not covered" and removes the ack.
- A HIGH diff finding is resolved by changing the line, or, for a reviewed false
  positive, by a comment on the same line:
  `security-review: allow <RULE-ID> <reason>` (visible in the diff and in git
  history). A code-scanning alert is resolved by fixing it or dismissing it in
  the alert, which GitHub audits.
- Release pull requests (`release/vX.Y.Z` into `main`) are judged only on what
  the release branch adds on top of `develop`, whose commits already passed the
  gate.
- Automation working under the maintainer's account must never add
  `security-ack`: the label is the maintainer's own decision. GitHub cannot
  tell such automation from the maintainer while they share an account; once
  automation moves to its own account or GitHub App, the `ackers` list enforces
  this by itself.

**Safety of the workflow.** It runs on `pull_request` and `merge_group` only (no
`pull_request_target`). The gate script and the path list are checked out from
the **base** commit, so a pull request cannot loosen the rules it is judged by,
and no code from the pull request runs in the gate job (the diff is read as
data). Fork pull requests get a read-only token: the verdict is in the check and
the job summary, and the label and comment are skipped. The gate fails closed
on any API or git error and on a merge-queue branch it cannot parse. The API
lists at most 3000 changed files, so a pull request of 3000 files or more (a
release branch far ahead of `main`) is diffed with git instead: the gate fetches
the base and head commits into its base checkout, never checks them out or runs
anything from them, and evaluates the same rules and ack digest on that list. 

**Pinning the required check to the real workflow.** Branch protection requires
a check *named* `security-gate` from the GitHub Actions app. On `pull_request`
events GitHub runs the workflow files of the pull request itself, so a pull
request can rewrite `security-gate.yml` (or add any workflow with a job named
`security-gate`) and report a green check under that name. The gate script
cannot defend against this; GitHub can. An organization ruleset rule
**Require workflows to pass before merging** runs
`.github/workflows/security-gate.yml` from a fixed branch of this repository
for every pull request into `develop` and `main`, whatever the pull request
changes, and only that run satisfies the rule. Owner setup (organization
owner; rulesets with required workflows are organization-level only):

1. Wait until this hardened gate is on `develop` (the ruleset runs
   `develop`'s copy of the workflow).
2. Organization **Settings > Repository > Rulesets > New branch ruleset**:
   name `security-gate required workflow`, enforcement **Active**, bypass
   list **Repository admin** (the emergency override below), target
   repositories `openctem`, target branches `develop` and `main`.
3. Enable **Require workflows to pass before merging**, add workflow
   repository `openctemio/openctem`, path `.github/workflows/security-gate.yml`,
   ref `refs/heads/develop`. Save.

   The same through the API:

   ```sh
   gh api -X POST orgs/openctemio/rulesets --input - <<'JSON'
   {"name": "security-gate required workflow", "target": "branch", "enforcement": "active",
    "conditions": {"ref_name": {"include": ["refs/heads/develop", "refs/heads/main"], "exclude": []},
                   "repository_name": {"include": ["openctem"], "exclude": []}},
    "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
    "rules": [{"type": "workflows", "parameters": {"do_not_enforce_on_create": false,
      "workflows": [{"repository_id": 1150018630, "path": ".github/workflows/security-gate.yml",
                     "ref": "refs/heads/develop"}]}}]}
   JSON
   ```
4. Open a throwaway pull request that changes nothing sensitive and check
   that the ruleset run appears and passes, also in the merge queue; on a
   sensitive one, check that adding `security-ack` re-runs the check
   (`Security Gate Label`) and that it turns green
   (`merge_group` is in the workflow's triggers, which the ruleset needs).
5. Then remove `security-gate` from the required status checks of `develop`
   and `main` in branch protection: the name-only requirement adds nothing once
   the workflow is required. Keep `security-gate-label.yml`: the pinned run
   never starts on a label, so without it an ack only takes effect on the next
   push or a manual re-run.

Until the ruleset exists, a pull request that edits `security-gate.yml` is the
residual risk: it is `ci-release` sensitive, needs the ack on its exact head
commit, and the reviewer must read the workflow change before acking.

**Emergency override.** An administrator can merge a pull request whose gate is
red with **Merge without waiting for requirements (bypass rules)** (or by
removing the check from branch protection for the incident). GitHub records the
bypass in the organization audit log. Afterwards add `security-ack` to the merged
pull request, or open a follow-up issue that explains the bypass, so every
security-sensitive change carries a visible decision.

**Changing the list.** Edit `.github/security-paths.yml`, then run
`python3 .github/scripts/security_gate.py codeowners --write`, and
`python3 .github/scripts/security_gate_test.py` (the tests also fail when a
pattern matches no tracked file). The change itself is security-sensitive; it
takes effect for pull requests opened against the base after it merges.

### Path filtering

One rule set, in [`.github/scripts/changed.sh`](../../../.github/scripts/changed.sh),
decides the outputs `api` and `web` for every workflow (`docs` is informational):

| Changed path | api | web |
|--------------|-----|-----|
| Documentation: `*.md` anywhere, `api/docs/**`, `.claude/**`, `web/.claude/**` | | |
| `api/**` | ✓ | |
| `web/**` | | ✓ |
| Shared: root `Makefile`, `go.work*`, `.github/**`, `deploy/**` | ✓ | ✓ |
| Anything else (`.githooks/`) | | |

Two more outputs choose the tier (see [Tiers](#tiers)):

| Output | True when |
|--------|-----------|
| `migrations` | the change touches `api/migrations/` or `api/deploy/postgres/` |
| `full` | every event except `pull_request`; on a PR, when it has the `ci:full` label or changes a CI definition (`.github/workflows/`, `.github/scripts/`, `.github/actions/`) |

The label is read live through the API, so adding `ci:full` and re-running the
jobs is enough; a re-run otherwise sees the labels of the original event.

Documentation is matched first, so an RFC, a changelog fragment or a README
never starts the Go or web suites, also in the merge queue. A docs-only PR runs
Docs check, Secret Scanning, Workflow Lint, the security gate and API CI's
`changes` job (which also runs the changelog check), and the `… OK`
aggregators pass. One exception: `api/docs/configuration/environment-variables.md`
is generated and compared by a Go test (`TestEnvDocsUpToDate`), so it counts as
API code. Tests: `.github/scripts/changed.test.sh` (run by Workflow Lint).

The diff range depends on the event:

| Event | Range |
|-------|-------|
| `pull_request` | the PR against its base (`origin/<base>...HEAD`) |
| `push` | `before..HEAD` |
| `merge_group` | `merge_group.base_sha..head_sha`, exactly the queued PR |
| schedule, manual dispatch, tag, a branch's first push, missing SHAs | everything runs |

How each workflow uses the outputs:

| Workflow | Scoping |
|----------|---------|
| API CI | always starts; real jobs run when `api` (which ones: [Tiers](#tiers)) |
| Web CI | always starts; `API contract` runs when `api` or `web`; `Web checks` when `web`, or when an API change changed the generated contract |
| CodeQL | Go when `api`, JS/TS when `web` (PR); nothing in the merge queue; both on push and weekly |
| All-in-one CI | always starts; builds when `api` or `web` (both images are built from the whole component directory) and `full` |
| Repository Security | always runs (secret scan diff-scoped on PR and merge queue) |
| API Security | `on.paths`: `api/**` + shared files, minus `**/*.md` and `api/docs/**`. Does not start at all for a web-only or docs-only change |
| Web Security | `on.paths`: `web/**` + shared files, minus `**/*.md`. Does not start at all for an API-only or docs-only change |

Workflows that carry a required check never use `on.<event>.paths`: a workflow
skipped that way leaves its required checks *Pending* forever. They always start,
and a job skipped by `if:` reports success to its aggregator. API Security and
Web Security carry no required check, so they can use `on.paths`. If you change
the shared list, change it in `changed.sh` and in both of those `paths:` lists.

A newer push to a PR cancels that PR's older run in every workflow
(`cancel-in-progress` only for `pull_request`); merge-queue runs, branch pushes,
tags and scheduled runs are never cancelled.

### Merge queue

1. A PR runs CI as usual (`pull_request`). When it is green and approved,
   **Merge when ready** adds it to the queue.
2. The queue creates `gh-readonly-queue/<base>/pr-<n>-<sha>`: the base (or the
   group ahead of it in the queue) plus this PR, and fires `merge_group`
   (`checks_requested`).
3. API CI, Web CI, All-in-one CI and Repository Security run the full tier (see
   [Tiers](#tiers)) on that ref; CodeQL only reports `CodeQL OK`. `changed.sh`
   diffs `base_sha..head_sha`, so a queued web-only PR runs only web jobs, as it
   did on the PR.
4. Every required check reports on every queue ref: the five `… OK`
   aggregators run with `if: always()` and pass when their jobs were skipped;
   Secret Scanning and Workflow Lint are unconditional jobs. Nothing stays Pending.
5. When all of them pass, the queue fast-forwards the base branch to the commit it
   tested, and the `push` run (path-scoped, plus CodeQL on both languages)
   refreshes the branch's baseline. On `develop`, API CI, All-in-one CI and Web
   E2E first ask `.github/scripts/queue-verified.sh` whether the merge queue
   already passed this workflow on this exact commit (a `merge_group` run, same
   workflow file, same SHA, conclusion success; only GitHub creates such runs).
   If so they skip their test jobs: the queue ran the same workflow file on the
   same tree. The push still keeps develop's caches current (`Go cache
   (develop)` fills the Go cache when there is none for the current `go.sum`;
   Web E2E still builds its images, which writes the layer cache). Any doubt
   (no such run, an API error) runs the workflow in full. CodeQL, Web CI and
   the security scans always run on push.
6. A failure removes the PR from the queue; the groups behind it are rebuilt.

### Tiers

Every PR is tested twice (on the PR, then in the queue) on a shared pool of
hosted runners (about 60 concurrent jobs for the organization), and many PRs are
open at once, so a PR runs only what catches most breakage early and the queue
runs everything. Self-hosted runners are not used: this is a public repository,
and a fork PR would run code on the host.

| Tier | Events | API CI | Web CI | All-in-one CI | Web E2E | CodeQL |
|------|--------|--------|--------|---------------|---------|--------|
| Fast | `pull_request` | `API static checks` (gates + vet, staticcheck, golangci-lint) + `Tests (Postgres + Redis)`: the whole suite against Postgres and Redis in 6 shards **without** `-race`, so isolation tests fail on the PR (decision D-30). `Tests (least-privilege DB role)` and `Migrations (PostgreSQL 18)` only when `migrations` | `Web checks`, `Web tests` | build skipped | only with `run-e2e`, or when `web/e2e/` changed | changed language(s) |
| Full | `merge_group`, push to `develop`, a PR with `ci:full` or a changed CI definition | the suite in 8 shards **with** `-race`, the least-privilege suite, PostgreSQL 18, `Release Binaries` (not on a PR); Docker build on `main` | `Web checks`, `Web tests`; `next build` on push | images built and smoke-tested | Playwright in 4 shards (`web/` or `api/` changed) | queue: none (the PR head was analysed); push: both |

**Forcing the full tier on a PR:** add the `ci:full` label, then re-run all jobs
of the workflow run (or push). Use it for a risky change to concurrency, SQL
grants or the images before it reaches the queue. A PR that changes a workflow
or a CI script always runs the full tier.

What runs per pull request (jobs started, including the ~10 s `changes` and
`… OK` jobs; the merge queue still runs the full set):

| PR changes | Fast tier | Full tier (`ci:full`) |
|------------|-----------|-----------------------|
| docs only | 16 | 16 |
| `web/` only | 23 | 30 |
| `api/` only, no migration | 26 (30 when the generated contract changed) | 44 (48) |
| `api/` with a migration | 33 (37) | 44 (48) |
| `api/` + `web/` | 32 | 50 |

The `… OK` aggregators pass when a job was skipped because its area did not
change, but when the area did change they also require that **this event's
tier ran and passed**. `API CI OK` and `All-in-one OK` fail any `merge_group`
or push run that did not compute the full tier; in the queue `API CI OK` fails
unless the race-enabled suite, the least-privilege suite, PostgreSQL 18 and the
release binaries succeeded, and `All-in-one OK` fails unless the image build
succeeded. Nothing reaches `develop`/`main` on the fast tier alone.

Caches: GitHub lets a run restore caches of its own ref, of the default branch
and, for a pull request, of its base branch. A merge-queue ref is none of
these for `develop`, so it restores nothing, and what it writes no other run can
read. API CI therefore neither restores nor saves the Go cache in the queue,
and the Web E2E layer cache (`web/e2e/ci/docker-bake.hcl`) is written by pushes
to `develop` only; pull requests read develop's. Before, queue and PR refs held
about 7 of the 10 GB cache store and evicted develop's entries.

Concurrency: a newer push to a PR cancels that PR's older run
(`cancel-in-progress` only for `pull_request`). Merge-queue runs are never
cancelled, because a cancelled required check ejects the group. Branch pushes,
tags and schedules are never cancelled either.

PR-only steps (Migration Safety, golangci-lint on new code) are skipped in the
queue: they already ran on the PR. API Security and Web Security do not run in
the queue (no required check; the PR and the push scan the change).

### Toolchain versions

- **Go:** every `actions/setup-go` step uses `go-version-file: api/go.mod`, which
  reads the `toolchain` directive (currently `go1.26.10`). setup-go sets
  `GOTOOLCHAIN=local`, so this is exactly the Go that tests, CodeQL, govulncheck
  and the release binaries use. `api/Dockerfile` and `api/Dockerfile.admin-cli`
  pin their `golang:` base image separately: bump them with `go.mod`.
- **Node:** every `actions/setup-node` step uses `node-version-file: web/.nvmrc`
  (`26`), the same major as `web/Dockerfile` (`node:26-alpine`). Node 25+ ships
  its own `localStorage`; `web/src/test/setup.ts` points Vitest back at jsdom's.

### Supported PostgreSQL

**PostgreSQL 16, 17 and 18 are supported; 17 is recommended.** The matrix:

| Version | What CI runs | When |
|---|---|---|
| 17 | The whole suite (shards, `-race` in the queue), the least-privilege suite | every pull request and merge group |
| 18 | Every migration plus the schema probes (`Migrations (PostgreSQL 18)` in API CI), and the DB-backed packages as the app role (`api-pg-compat.yml`) | full tier of API CI; nightly and on a push to `develop` that changes migrations |
| 16 | The DB-backed packages as the app role (`api-pg-compat.yml`) | nightly and on a push to `develop` that changes migrations |

16 and 18 run less often than 17 on purpose, to keep the cost of a pull request down; a failure there is found within a
day, with the commit range in the run history. A migration that needs a newer major than 16 (new syntax, a catalog
column) fails the 16 job: write it so 16 can run it, or raise the supported floor in the same pull request, in this section
and in the install documentation. The images are pinned by digest in `.github/ci-images.txt` and mirrored; bump the
digest in `api-ci.yml` (18) and `api-pg-compat.yml` (16 and 18) together with it.
### Tool pin freshness

Linters, scanners, signing tools and the like are pinned inline (a version in a
workflow `env`, a Makefile variable, a Dockerfile `ARG`), where Dependabot does not
look. `.github/tool-pins.tsv` lists each pin: the tool, its GitHub repository, whether
upstream versions come from releases or tags, the highest major version we follow
(`golangci-lint` stays on v1 on purpose, its v2 does not read our config), the file
and a regular expression that captures the pinned version, and flags (`checksum`: a
SHA-256 sits next to the pin and changes with it; `optional`: the pin may not exist
yet). Add a row whenever you pin a new tool inline.

The weekly **Tool Pin Freshness** workflow runs `.github/scripts/tool-pins.py`. It
opens or updates one issue labelled `tool-pins` with a table of the tools that have a
newer stable release (release candidates are ignored) and closes the issue when
nothing is behind. It uses the `GITHUB_TOKEN` of the job with `contents: read` and
`issues: write`, so it never opens a pull request: a person or an agent bumps the
pins in one pull request and CI runs on it, which is why it needs no GitHub App. A
pin the script cannot find fails the run instead of passing silently (a renamed
variable would otherwise turn the check into a check of nothing). The Workflow Lint
job runs `.github/scripts/tool-pins.test.sh`. Run it by hand with
`GH_TOKEN=$(gh auth token) python3 .github/scripts/tool-pins.py`.
### Upgrade test

`api-upgrade-test.yml` runs `.github/scripts/upgrade-test.sh`, which does what an operator does on upgrade day,
on a scratch PostgreSQL 17 database:

0. before any database work, refuses a migration of this tree numbered at or below the previous release's highest
   version that the release does not have: `migrate up` applies only versions above the current one, so an upgraded
   install would skip it silently (`--check-order` runs only this step, without a database);
1. bootstraps the roles and applies the **previous release's** migrations (read from its git tag with `git archive`)
   as the non-superuser migrator, then checks `schema_migrations` says that release's highest version and not dirty;
2. loads representative rows, `api/scripts/upgrade-test/seed.sql`: three tenants with members and a role grant,
   75 assets, 240 findings in several statuses, sources and severities, a sensor per tenant and 150 audit rows;
3. applies **this tree's** migrations as the migrator and re-runs the roles script, as the `db-roles` and `migrate`
   services of the Compose stack do;
4. asserts that the version is this tree's highest migration and not dirty, that `schema_migrations` has one row,
   that no key table (`tenants`, `users`, `tenant_members`, `user_roles`, `assets`, `findings`, `sensors`,
   `audit_logs`, `roles`, `permissions`) lost a row, that the app role still reads the data, and that the API built
   from this tree starts against the upgraded database as the app role and answers `/health` and `/ready` with 200.

The release to start from is the newest `vX.Y.Z` tag reachable from the commit, other than a tag on the commit itself;
the workflow checks out every tag, and `--prev vX.Y.Z` (or the `prev` input of a manual run) picks another, for example
the release before last. The seed file runs against the **previous** release's schema, so it uses only columns every
released schema has (identifiers, NOT NULL columns without a default, a few stable optional ones): add a table or a
column to it only after the release that introduced it is the oldest one you still upgrade from. A table the seed
cannot fill (a constraint it does not know) is left out rather than faked.

It runs nightly and on release branches, not on pull requests, because it builds the API (about two minutes) and a
migration chain; a migration that fails only on a populated table, or only after the previous release's data, is found
within a day, and always before a release PR merges. Run it locally with a scratch PostgreSQL that has the
`postgres` superuser and trust authentication:

```bash
export SUPER_URL=postgres://postgres@localhost:5432/upgrade_test?sslmode=disable \
  MIGRATOR_URL=postgres://openctem_migrator@localhost:5432/upgrade_test?sslmode=disable \
  APP_ROLE_URL=postgres://openctem_app@localhost:5432/upgrade_test?sslmode=disable
(cd api && go build -o /tmp/openctem-server ./cmd/server)
bash .github/scripts/upgrade-test.sh --server-bin /tmp/openctem-server   # needs migrate, psql, Redis
```

The database must be empty; the script refuses one that already has a schema. Its tag selection and refusals are
tested by `.github/scripts/upgrade-test.test.sh` in **Workflow Lint**.

### Release-note labels

`pr-hygiene.yml` (job Release-note labels) runs `.github/scripts/pr-labels.py` on every same-repository pull request and
adds these labels, so the release notes can show an operator what to read before upgrading:

| Label | Added when the PR |
|---|---|
| `notes:migration` | adds or changes a `api/migrations/*.up.sql` |
| `notes:destructive-migration` | adds a line to a migration that drops a table, column or schema, truncates, renames, or changes a column type (SQL comments are ignored; deleting a migration does not count) |
| `notes:identity` | changes finding identity or fingerprint code (`api/pkg/domain/vulnerability/identity*.go`, `fingerprint*.go`, `secret_fingerprint*.go`, `api/internal/app/ingest/identity*.go`) or the `github.com/openctemio/ctis` version in `api/go.mod` (tests alone do not count) |
| `notes:api-contract` | changes a file in `api/internal/infra/http/handler/` or `routes/`, or `api/pkg/sensorproto/` (tests do not count) |

The labeler reads the changed files through the API as data and runs from the base commit, so
no pull request code runs; a fork pull request gets a read-only token, is skipped, and a
maintainer adds the labels by hand. Labels are only added, never removed: add one by hand when a
rule misses a change, remove one by hand when it over-reports. The destructive label is
informational; the `Migration Safety` check and the `allow-destructive-migration` label still
decide whether a destructive migration may merge.

The release train groups the changelog fragments by these labels. The plan job runs
`.github/scripts/release/fragment-labels.py`, which finds the pull request that added each
fragment and keeps its `notes:*` labels, and `api/scripts/changelog.py preview --labels FILE`
prints an **Upgrade notes** block ahead of the categories: the section titles of the fragments
under "Destructive migrations (read before upgrading)", "Database migrations", "Finding identity
and fingerprint changes" and "API contract changes". The follow-up PR that folds the fragments
into `api/CHANGELOG.md` does the same: `python3 .github/scripts/release/fragment-labels.py --out
/tmp/labels.json` (with `GH_TOKEN` set), then `python3 api/scripts/changelog.py release vX.Y.Z
--labels /tmp/labels.json`. A fragment whose pull request cannot be found is named on stderr and
only lacks its heading. Without `--labels` the notes are unchanged. The tests are
`.github/scripts/release/tests/test_release_note_sections.sh`, run by Release Tooling.

### CI image mirror

Shared GitHub runner IPs exhaust the anonymous pull quotas of `public.ecr.aws`
(`toomanyrequests: Data limit exceeded`) and Docker Hub, and a job then fails
before it runs a single step. CI therefore pulls its third-party images from
GHCR, authenticated with the job's `GITHUB_TOKEN`:

- `.github/ci-images.txt` lists each image as `<source>@sha256:<digest> <name>:<tag>`.
  `ci-image-mirror.yml` copies it with `crane copy` to
  `ghcr.io/openctemio/mirror/<name>:<tag>` (manifest bytes kept, so the digest is
  the upstream one) and verifies the digest. A `docker.io/library/` source falls
  back to `public.ecr.aws/docker/library/`. The daily run re-copies anything
  missing and adds a notice when an upstream tag has moved past its pin.
- The same workflow mirrors every digest-pinned base image of the Dockerfiles
  on `main` of openctemio/sensor (`.github/scripts/ci-image-bases.sh`: only
  `public.ecr.aws/docker/library/*` and `gcr.io/distroless/*`) as
  `<name>:sha256-<hex>`, so a bumped base is mirrored within a day of its merge
  without editing the list, and never moves a tag something else pins. The
  sensor and asset-collector builds (CI, image smoke test and Docker Publish)
  swap each base for its mirror copy through buildx named contexts
  (`scripts/ci-mirror-contexts.sh` there) and fall back to the upstream while a
  digest is not mirrored yet. asset-collector is private (the job token cannot
  read it), so its bases are in the list.
- Service containers (`api-ci.yml`, `allinone-ci.yml`, `docker-publish.yml`), the
  Semgrep job container and the e2e stack (`web/e2e/ci/compose.yml`) use the
  mirror with `credentials:` from `GITHUB_TOKEN` (workflow `packages: read`).
- The mirror packages are **public**, so fork pull requests and the other
  openctemio repositories (sensor base images, the sdk-go sandbox test) pull
  them anonymously. A new package starts private: make it public once in the
  organisation's package settings; the mirror run warns while one is not.
- Jobs that build our Dockerfiles (their `FROM` lines stay on the upstream
  registries) log in first through `.github/actions/registry-login` (GHCR
  always, Docker Hub when `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` are set; both
  non-fatal), and direct `docker build` / `docker compose pull` steps run through
  `.github/scripts/retry.sh`, which retries with backoff only on registry
  rate limits and transient network errors.
- To add or bump an image: `crane digest <source>:<tag>`, edit the list (and any
  reference that pins the digest), merge; the push to `develop` mirrors it
  before the next CI run needs it.

### Workflow security

- **Every action is pinned to a full commit SHA** with a `# vX.Y.Z` comment
  (`uses: actions/checkout@<40-hex> # v7.0.1`). A tag or branch ref can be moved
  by whoever controls the action's repository, and the new code would run with
  the job's token and secrets; a SHA cannot. Workflow Lint runs
  `.github/scripts/check-action-pins.sh`, which fails on any unpinned `uses:`.
  Dependabot (`github-actions`, weekly, minor/patch grouped) bumps the SHA and
  the comment together. To add an action, resolve the release tag to its commit
  (`gh api repos/<owner>/<repo>/commits/<tag> -q .sha`) and pin that.
- **Least-privilege tokens.** Each workflow sets `permissions: contents: read`
  at the top; a job that needs more asks for it itself (for example
  `security-events: write` only on the jobs that upload SARIF, `contents: write`
  only on the job that publishes a release). The repository default for
  `GITHUB_TOKEN` is read-only as well.
- **No `pull_request_target`.** PR workflows run with the PR's read-only token
  and no secrets for fork PRs; nothing checks out a PR head with a write token.
- Downloaded tools are pinned by version and SHA-256 (betterleaks, actionlint, zizmor).

### Generated contract files

The web console compiles against files generated from the Go API. **None of them
is committed** (root `.gitignore`), so two pull requests can never conflict on
them and the merge queue can test several API changes in one group:

| File | Generated from | By |
|------|----------------|----|
| `api/api/openapi/swagger.yaml` | handler `// @Router` annotations and request/response types | `make -C api swagger` (swag, pinned) |
| `api/api/openapi/routes.txt` | the router | `tools/lint/openapicontract` `TestWriteRouteManifest` |
| `web/src/config/api-route-permissions.json` | the route gates | `tests/unit/route_permission_map_test.go` |
| `web/src/config/authz-matrix.json` | the catalog, the built-in roles, the role templates, the route gates, the data-scope registry | `cmd/gen-authz-docs` ([authorization-reference.md](../architecture/authorization-reference.md)) |
| `web/src/lib/api/generated/api.types.ts` | the spec | `web/scripts/generate-api-types.sh` |

`make -C api contract` writes the first four (needs Go), `npm run
generate:api-types` in `web/` the fifth (needs Node); **`make generate`** at the
root runs both, and **`make generate-docker`** does the same in throwaway
`golang`/`node` containers when the host has only Docker
(`scripts/generate-in-docker.sh`). Run it after pulling and after changing a
handler, a route or its gate. `npm run dev/build/type-check/lint/test` refresh
the web types when the spec is newer and stop with that hint when a file is
missing (`web/scripts/ensure-generated.mjs`). Everything that builds the web
console generates first: Web CI, Web E2E, All-in-one CI, Web Security's image
scan and Docker Publish use the composite action
`.github/actions/generate-contract` before `docker build web`. The web
Dockerfile itself does not generate (its context is `web/` only): build the
image after `make generate`, as `make allinone` does.

The checks, on the generated output:

- **API CI → OpenAPI Contract** (`api/scripts/check-openapi.sh`) generates the
  spec, then checks it against the handlers and the router
  (`tools/lint/openapicontract`): every annotation is in the spec and back,
  every documented operation is routed, every route is documented or in the
  shrink-only `api/openapi/undocumented-routes.txt`, path parameter names agree
  or are in `api/openapi/param-name-drift.txt`. The test jobs generate the spec
  too, for the tests that read it (the filter-param drift test).
- **Web CI → API contract** generates the files once per run and hands them to
  `Web checks` (artifact `contract`), which builds the TypeScript types and runs
  tsc, ESLint and Vitest (including the endpoint check against `routes.txt`)
  against them. For an API change it also generates the **base's** contract
  (merge base / queue base / previous tip) and compares:
  - when the contract changed, `Web checks` runs even though `web/` did not
    change, so the web is proven to compile against the new contract;
  - `tools/openapidiff` writes the difference to the job summary and to one
    pull request comment, updated on every push (job `API contract report`, the
    only job with a write token; it runs no pull request code, and fork pull
    requests only get the summary): operations removed or added, parameters
    that became required, request/response schemas that changed
    (`tools/lint/openapischema`; descriptions and `format` are ignored because
    swag is not byte-reproducible across machines), **route gate changes** of
    the web permission map (review them as authorization changes) and
    registered routes added or removed. Breaking changes are reported, not
    failed: a reviewer decides whether one is intended.

Locally:

```bash
make generate          # every contract file (Go + Node)
make generate-docker   # the same, with only Docker
make check             # generate, the OpenAPI contract check, then tsc
```

**Deploying a bind-mounted checkout** (the API under air, the web under `next
dev`): a `git pull` that deletes or changes nothing generated still leaves the
files stale, so run `make generate-docker` (or `scripts/generate-in-docker.sh
<checkout>`) after every pull. `next dev` and air pick the new files up.

### What the API jobs check

| Job | Notes |
|-----|-------|
| *All of the rows down to Test shards are steps of one job, `API static checks`.* | |
| Migration Safety | PRs only. Flags destructive migrations against the base. |
| Migration Versions | `.github/scripts/check-migration-versions.sh` (tests: `check-migration-versions.test.sh`). Fails if two migrations share a version, and, on a PR or in the merge queue, if a migration the change adds is not above the base's highest version (golang-migrate silently skips lower versions on databases already past them). In the queue the base is `merge_group.base_sha`, so two queued PRs that picked the same number cannot both land: the second is told to renumber to max+1. A migration baseline (`NNNNNN_baseline`, RFC-053) may sit at or below the base's highest version when it is the lowest version left in the tree. On a PR, a version below the base's highest, or one a base migration also uses, is only a warning: the PR's migrations are renumbered when it is queued. Two migrations of the same PR with one version still fail. |
| Renumber this PR's clashing migrations | PR only, in `API static checks` and every DB test shard: `.github/scripts/pr-migration-renumber.sh` (tests: `pr-migration-renumber.test.sh`). CI tests the PR merged into its base; when develop has taken one of the PR's migration numbers since, the runner's copy of the PR's added migrations is renumbered above the base (in order, same width, references to the old file stems rewritten), and a byte-identical copy of a base migration (a stacked PR's inherited file) is ignored. Nothing is committed; each change is a warning annotation. The PR stays green, and the real renumber happens when the PR is queued. The merge queue and pushes never renumber: there, a clash fails `Migration Versions`. |
| SQL Schema Drift | `api/scripts/check-sql-schema.sh`: prepares every SQL statement against a migrations-only database. |
| Security Gates | `api/scripts/security-lint.sh` (checks out `sensor` and `sdk-go` alongside), tenant-scope analyzer, sensor vocabulary guard. |
| OpenAPI Contract | See above. |
| Gateway Routing | `api/deploy/gateway/smoke-test.sh` (every plane's routing against stub upstreams) + renders the production compose files. That `planes.caddy` matches the plane table is a unit test (`routes/plane` `TestGatewayPlanesFile`). |
| Test shards | `.github/scripts/go-shard.sh check` proves the test shards below (8, 6 and 3) cover every package and every top-level test of a split package exactly once. |
| Lint (steps of `API static checks`; the golangci-lint cache and the staticcheck binary are cached) | `go vet`, staticcheck, and golangci-lint v1.64.8 on **new** code only (PRs: `make lint-new` with `--new-from-rev` against `.github/scripts/effective-base.sh`). `make -C api lint-ci` runs the same locally. |
| Tests (Postgres + Redis) | PRs (when `api/` or shared files change), merge queue and pushes. `go test -timeout 20m` against Postgres 17 + Redis 7 service containers. Full tier: `-race`, eight parallel shards; fast tier (PR): no `-race`, six. The four packages that hold most of the run time and run their tests one after another (`tests/unit`, `tests/integration`, `internal/infra/http/routes`, `internal/infra/postgres`) are split by top-level test name over every shard, each slice in its own `go test` process so it keeps the database to itself; every other package goes whole to one shard (`.github/scripts/go-shard.sh`, run by `go-shard-run.sh`). Before, `tests/integration` alone held one shard for about 16 minutes while the others finished in 7 to 14. Both splits run the same tests, each with `OPENCTEM_TEST_DB_REQUIRED=1` so `internal/testdb` fails instead of skipping, then `.github/scripts/check-db-test-skips.sh` fails the job if any test skipped itself for a missing or unreachable database. |
| Tests (least-privilege DB role) | Sharded the same way (3 + 3 shards). Full tier, and on a PR that changes `api/migrations/` or `api/deploy/postgres/` (when `api/` or shared files change). Bootstraps a fresh database with `api/deploy/postgres/least-privilege-roles.sql`, applies every migration as `openctem_migrator`, then runs the DB-backed suite as `openctem_app` (DML only). It fails if a migration needs a superuser or the API needs more than DML. See `api/docs/deployment/database-roles.md`. |
| Migrations (PostgreSQL 18) | Same tiers as the least-privilege suite. Applies every migration to a fresh PostgreSQL 18 database (the next major; the suites above run on 17), then runs the schema probes that read the catalog (`TestCheckSensorRename`). PostgreSQL 18 records each column's NOT NULL as a `pg_constraint` row (`contype = 'n'`), so a migration or probe that reads `pg_constraint` must filter on `contype`. The image comes from the CI mirror, or its upstream with the same digest until the mirror has it. |
| Release Binaries | Merge queue and pushes to `develop`. Builds and uploads static linux/amd64 `cmd/server` and `cmd/bootstrap-admin` binaries. |

**Pushes to `main`** run no heavy suite: `main` receives only release and hotfix PRs that the merge queue and the PR-into-`main` scans already gated, and the tag build (`docker-publish.yml`) has its own image guard. A push to `main` runs CodeQL (baseline of the default branch), Repository Security, PR hygiene, Release Tooling, the CLA and observability checks (path-filtered), and the release workflows; API CI, Web CI, All-in-one CI, Web E2E and the `paths:`-filtered API/Web Security scans run on `develop` pushes only. The image scans of API/Web Security still run weekly and on a PR into `main`.

All Go jobs run with `GOWORK=off` and `working-directory: api`.

## Work done once per run

Setup that every job of a run needs is done once and handed over:

- **OpenAPI spec** (`api-ci.yml`, job `spec`): `make swagger` takes 1.5-2
  minutes and every test and least-privilege shard ran it (14 shards on the
  full tier; in the merge queue nothing is cached). One job generates it and
  uploads `openapi-spec`; the shards download it.
- **Images** are built once per content key across workflows
  (Build images once, in `build-images.yml`).
- **Contract files** are generated once per workflow and passed on as the
  `contract` artifact (`web-ci.yml`); `build-images.yml` generates them once for
  the web and console images together.

Not shared on purpose: the Go and npm caches (a merge-queue ref can neither read
nor share them, so a job there starts cold regardless), `go vet`/`staticcheck`
(static job) versus golangci-lint (`//nolint` handling differs), and the
`tools/lint` guards that run both as named gates in `API static checks` and
inside the test shards (removing them from the shards would make the shard
cover-every-test check depend on the static job).

## Releases

**One tag, `vX.Y.Z` on `main`, releases the whole product.** API and web always
share the version. There is no separate web release any more. The rule, the
cadence and the tooling are [RFC-037](../rfcs/RFC-037-versioning-and-release-train.md);
how to run a release is [Versioning and releases](../architecture/versioning-and-releases.md).

- **Release train every other Monday**, plus immediate patch releases for
  security and critical fixes. Run **Release Train** (Actions); do not tag by
  hand.
- `docker-publish.yml` and `release.yml` both trigger on `v*`.
- A tag's checkout defaults to its own version: the release branch carries
  `versions.yaml` `platform.release: vX.Y.Z`, synced into
  `api/deploy/.env.example` and the compose files, so `setup.sh` on a `vX.Y.Z`
  checkout installs `vX.Y.Z`. `develop` gets the bump when `main` is merged
  back after the tag.
- `ui/vX.Y.Z` tags are the old `openctemio/ui` tags, imported with its history.
  They release nothing: the `v*` glob does not match across `/`. Never create one.
- `vX.Y.Z-staging` (or a manual dispatch with `environment: staging`) publishes
  `vX.Y.Z-staging` + `staging-latest` instead of `vX.Y.Z` + `latest`.
- Releases v0.1.x–v0.8.0 on this repository's Releases page are the API releases
  from before the merge; the old web releases stay on the archived `openctemio/ui`.

```bash
# a release: Actions > Release Train > Run (dry_run first), or
gh workflow run release-train.yml --ref develop -f dry_run=false

# manual publish of an existing version (e.g. a staging build)
gh workflow run docker-publish.yml -f version=v0.9.0 -f environment=staging
```

### Images

All images go to GHCR, are multi-arch (linux/amd64 + linux/arm64), are built on a
**native** runner per architecture and smoke-tested there (config arch, ELF
`e_machine`, the binary executes) before anything is pushed, then merged into one
manifest list per tag, signed with cosign (keyless) and given an SPDX SBOM that
is attached to the GitHub Release, and a signed SLSA build provenance
(`actions/attest-build-provenance`, stored in the registry next to the image;
`gh attestation verify oci://<image>:<tag> --owner openctemio`).

Before the push, each image also passes the **image guard**
(`.github/scripts/image-guard.sh`), which the merge queue runs on every image
build too (`allinone-ci.yml`):

- its unpacked size stays under the component's budget (set about 15% above
  its size; raising one needs the reason in the commit message), so a stray
  `chown -R`, a duplicated binary or a toolchain left in the runtime stage
  fails instead of shipping;
- it runs as a non-root user (the gateway is the one listed exception, for
  its root-owned volumes);
- no file is setuid or setgid;
- no OS package has a HIGH or CRITICAL advisory with a fix (trivy). Advisories
  in application dependencies are printed as warnings; govulncheck and
  `npm audit` gate those in API and Web CI.

The guard reads the filesystem with `docker export`, never a shell inside the
image, so images without a shell are checked the same way.

| Image | Built from | Contents |
|-------|-----------|----------|
| `ghcr.io/openctemio/openctem-api` | `api/Dockerfile` (`production` target) | API server, port 8080 |
| `ghcr.io/openctemio/openctem-web` | `web/Dockerfile` | Next.js console, port 3000 |
| `ghcr.io/openctemio/openctem` | `deploy/allinone/` FROM the two above + `api/deploy/gateway` | All-in-one: API + web + Caddy gateway. `GATEWAY=on` (default) serves only 443; `GATEWAY=off` serves 8080 + 3000. Postgres/Redis external. |
| `ghcr.io/openctemio/migrations` | `api/Dockerfile.migrations` | One-shot migration runner |
| `ghcr.io/openctemio/seed` | `api/Dockerfile.seed` | Seeding utility |
| `ghcr.io/openctemio/admin-cli` | `api/Dockerfile.admin-cli` | Admin CLI |

**Legacy names.** During a transition window (two releases, per the root
README) `ghcr.io/openctemio/api` and `ghcr.io/openctemio/ui` receive the same
manifests as `openctem-api` and `openctem-web` (`crane copy`), so existing
compose files, Helm values and `docker pull` lines keep working. The window
ends when the `legacy` field of the matrix entry in `docker-publish.yml` is blanked.
The legacy names are also the only ones that hold v0.8.0 and earlier. The copy
is best effort: when it is refused the step warns and the release goes on
(v0.9.0 has no `ui` copy). The shipped Compose file and Helm values use the
current names.

**Docker Hub** mirroring (`mirror-to-dockerhub`) runs only when the
`DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` secrets are set. They currently are not,
so bare `openctemio/<name>` references (Docker Hub) do not resolve: always use
the `ghcr.io/openctemio/…` names.

Verify a signature:

```bash
cosign verify ghcr.io/openctemio/openctem:vX.Y.Z \
  --certificate-identity-regexp '^https://github.com/openctemio/openctem/.github/workflows/docker-publish.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Release archives

`release.yml` calls `release-dist.yml`, which runs
`.github/scripts/release/build-dist.sh` (the same script a pull request
dry-runs) for:

- `openctem-server`, `openctem-gateway`, `openctem-web`, `openctem-console`
  archives for linux/amd64 and linux/arm64 (web and console on a native runner
  per arch: their bundles hold native modules);
- `bootstrap-admin` for linux, darwin (amd64, arm64) and windows/amd64;
- `openctem-image-kit` (`deploy/airgap`).

Go builds are static (CGO off), `-trimpath`, with the commit time as build
time and as every archive entry's time: the same tag gives byte-identical
archives. golang-migrate, Caddy (with layer4) and swag are built at the
versions their Dockerfiles pin. Release then writes an SPDX SBOM per archive
(syft), `checksums-sha256.txt` over archives and SBOMs, signs it keyless
(`checksums-sha256.txt.sigstore.json`, identity
`.github/workflows/release.yml@refs/tags/vX.Y.Z`) and attests SLSA build
provenance for every archive (`gh attestation verify <archive> --owner openctemio`).
Install guide: [binary-install.md](../deployment/binary-install.md).

Docker Publish adds, on a production release, the offline image bundle: one
`openctem-image-<name>-<version>.oci.tar` per image (an OCI layout with the
multi-arch index and its signature and attestations, under the 2 GiB release
asset limit) and `openctem-images-<version>.txt` with its Sigstore bundle
([air-gapped.md](../deployment/air-gapped.md)).

## Local equivalents

From the repository root (see the root [`Makefile`](../../../Makefile), `make help`):

```bash
make setup       # go mod download (api), npm ci (web), make hooks
make hooks       # git config core.hooksPath .githooks
make lint        # make -C api lint-ci; web lint + type-check
make test        # go test (api), vitest (web)
make build       # go build (api), next build (web)
make check       # OpenAPI contract + generated web types
make allinone    # build openctem-api:local, openctem-web:local, openctem:local
make api-<t>     # any api/Makefile target, e.g. make api-swagger
make web-<s>     # any web npm script, e.g. make web-format
```

The git hooks in [`.githooks/`](../../../.githooks/) run on commit: `pre-commit`
type-checks and lint-stages `web/` when web files are staged and runs `gofmt` on
staged Go files; `commit-msg` rejects AI attribution lines.

## Branch strategy

```
main     release branch; v* tags are cut here
develop  integration branch; every PR targets develop
  feature/…, fix/…, docs/…, chore/…
```

1. Branch from `develop`, open the PR against `develop`. One PR may change both
   `api/` and `web/`.
2. Every required check green, then **Merge when ready** (merge queue).
3. Merge with a merge commit or squash, never "rebase and merge" for branches
   that contain merges.
4. Release: **Release Train** builds `release/vX.Y.Z` from a green `develop`
   commit and opens the PR to `main`; **Release Publish** tags `vX.Y.Z` on the
   merge commit (RFC-037).

Dependabot ([`.github/dependabot.yml`](../../../.github/dependabot.yml)) opens PRs
against `develop`: gomod for `/api` (and monthly for the compat harness), npm for
`/web`, and one github-actions entry for the root workflows.

## Secrets and settings

| Name | Kind | Used by |
|------|------|---------|
| `GITHUB_TOKEN` | built-in | GHCR push, release, SARIF upload |
| `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` | secret (optional) | authenticated base-image pulls; Docker Hub mirror when set |
| `SNYK_TOKEN` + `vars.ENABLE_SNYK` | secret + variable (optional) | Snyk jobs in API / Web Security |
| `RELEASE_TOKEN` | secret (recommended) | Release Train / Publish: pushes and PRs that start CI, the tag push that starts Docker Publish, the helm-charts PR. Fine-grained PAT or App token for `openctem`, `helm-charts`, `sdk-go`, `sensor`: Contents, Pull requests and Workflows read/write. Without it the release still works, with one extra click per PR and no helm-charts PR |
| `CLA_SIGNATURES_TOKEN` | organization secret (required for the `cla` check) | CLA: reads and updates the signature file. Fine-grained PAT, resource owner `openctemio`, repository `cla-signatures` only, Contents read/write |
| `vars.RELEASE_TRAIN_ANCHOR` | variable (optional) | The first train Monday (`YYYY-MM-DD`, default `2026-10-05`) |

The legacy `ui` GHCR package was created by `openctemio/ui`; this repository needs
**Write** in that package's "Manage Actions access" for the legacy copy to succeed
(without it the copy step warns and the release continues).

## Troubleshooting

- **A required check stays Pending.** Something added `on.paths` to a workflow
  that carries a required check, or dropped its `merge_group` trigger; gate the
  jobs through the `changes` job instead.
- **"Generated contract files are missing" / `api.types` not found.** The
  contract files are generated, not committed: `make generate` (or `make
  generate-docker`) at the root.
- **A merge conflicts on `swagger.yaml`, `api.types.ts` or
  `api-route-permissions.json`.** A branch from before these files left git:
  take the deletion (`git rm` the file) and regenerate locally.
- **golangci-lint reports issues you didn't touch.** The PR's base is stale; rebase
  on `develop` (lint diffs against `.github/scripts/effective-base.sh`).
- **govulncheck fails on every PR at once.** A new Go stdlib CVE: bump the
  `toolchain` directive in `api/go.mod` (CI follows it) and the `golang:` base
  image in `api/Dockerfile` and `api/Dockerfile.admin-cli`.
- **Image not found after a tag.** Check the Docker Publish run; the tag must match
  `v<major>.<minor>.<patch>[-suffix]`. Images for v0.8.0 and earlier exist only
  under the legacy `api` / `ui` names.
