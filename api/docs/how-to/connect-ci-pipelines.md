# Connect CI pipelines without a stored secret

GitHub Actions, GitLab CI, Azure Pipelines, Bitbucket Pipelines, CircleCI and
Jenkins (with its OpenID Connect provider plugin) jobs can send scan results
and fail on the platform's gate using the identity their CI provider gives
them (OIDC). Nothing secret is stored in CI. Design: [RFC-051](../rfcs/RFC-051-ci-runner-identity-and-gate.md).

You need `scans:ci:write` (owners and administrators).

## 1. Add CI trust

**Discovery > CI/CD > Trust and gate > Trust > Add trust** (also under
**Settings > Scanning > CI/CD integration**):

- **Provider**: GitHub Actions, GitLab CI, Azure Pipelines, Bitbucket
  Pipelines, CircleCI or Jenkins. Each asks for what names your CI
  organization (sections 3a to 3d); there is never an issuer that stands for
  every customer of a provider. For a self-managed GitLab or a Jenkins
  controller, enter its issuer URL. The platform fetches the issuer's keys
  over HTTPS through the outbound-request guard; an issuer on a private
  address needs its subnet in `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS` on the API.
- **Check a sample token** (in the dialog): paste a token from a job of that
  pipeline. The platform verifies its signature against the issuer's keys and
  shows its claims, the repository, ref, commit and run it reads from them,
  and whether the rules admit it. The sample is not stored and its id is not
  recorded (the same token can still be exchanged); a sample that expired
  since is still checked and shown as expired.
- **Owners** and/or **Repositories**: at least one. `acme` admits every
  repository of the `acme` organization or group; `acme/api, acme/web` only
  those; `acme/*` one level, `acme/**` any depth.
- **Branches and tags** (optional): for example `main, release/*`. A pull
  request is matched on its source branch.
- **Environments**, **Events** (optional): require a deployment environment or
  limit trigger events.
- **Protected branches and tags only**: admits only jobs on a protected ref.
  GitLab says so in the token (`ref_protected`). GitHub tokens do not, so on
  GitHub the switch requires **Environments**: list deployment environments
  whose deployment branch rules admit only protected branches and tags, and
  run the scan job in one of them.
- **Admit fork pull requests**: leave off. Events such as
  `pull_request_target` run fork code with your repository's identity.
- **Default branch**: the baseline used until the platform learns the
  repository's default branch.

The page then shows the pipeline snippet for the configuration.

The same through the API:

```bash
curl -X POST "$API/api/v1/ci/trust-configs" -H "Authorization: Bearer $SESSION" \
  -H 'Content-Type: application/json' \
  -d '{"name":"acme on GitHub","provider":"github","rules":{"owners":["acme"],"refs":["main","feature/*"]}}'
```

## 2. Run the scan in CI

The CI scanner is [openctemio/ci](https://github.com/openctemio/ci): the
`openctem-ci` binary, one signed image per tool (`ghcr.io/openctemio/ci-<tool>`)
and a bundle image (`ghcr.io/openctemio/ci`), a GitHub Action, GitLab CI
templates and examples for Azure Pipelines, Bitbucket Pipelines, CircleCI and
Jenkins. Capabilities: `sast` (semgrep), `sca` (trivy), `secrets`
(betterleaks), `iac` (trivy), `container` (trivy). Pin a release tag (the
examples use `v0.1.0`) or a commit, never a branch.

### GitHub Actions

```yaml
name: Security
on:
  pull_request:
  push:
    branches: [main]

jobs:
  openctem:
    uses: openctemio/ci/.github/workflows/scan.yml@v0.1.0
    with:
      capabilities: sast,sca,secrets,iac
      api-url: https://openctem.example.com
      tenant-id: <your organization id>
    permissions:
      contents: read
      id-token: write # lets the job request its OIDC token
```

Each capability runs in its own job and reports into one OpenCTEM CI run; a
final gate job asks the platform for the verdict. A single-job variant
(`uses: openctemio/ci@v0.1.0`) and every input are documented in
[openctemio/ci docs/github.md](https://github.com/openctemio/ci/blob/v0.1.0/docs/github.md).
Fork pull requests get no OIDC token from GitHub; the scan then runs without
uploading, which is intended.

### GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/openctemio/ci/v0.1.0/gitlab/templates/all.yml

variables:
  OPENCTEM_API_URL: https://openctem.example.com
  OPENCTEM_TENANT_ID: <your organization id>
```

Each job requests an ID token with the audience
`openctem:tenant:<organization id>`, which must equal the trust configuration's
audience. Step by step: [Run OpenCTEM security scans in GitLab CI/CD](gitlab-ci.md).

Merge requests from forks run in the fork's project by default, whose path does
not match your rules. If you run them in the parent project, turn on
**Protected branches and tags only** for configurations that must not admit
them.

### Azure Pipelines, Bitbucket Pipelines, CircleCI, Jenkins

See the [examples in openctemio/ci](https://github.com/openctemio/ci/tree/v0.1.0/examples)
(`azure-devops`, `bitbucket`, `circleci`, `jenkins`). In the trust configuration each of these providers asks
for what names your CI organization (Azure DevOps organization, Bitbucket
workspace, CircleCI organization, Jenkins controller issuer); Jenkins needs its
OpenID Connect provider plugin.

## Already have a tool's output file?

A job that already writes a file another tool understands does not need to
build a CTIS report. POST the file itself to
`/api/v1/ci/runs/{run_id}/results` with the token from the OIDC exchange
(`Authorization: Bearer <token>`); the format is read from the content
(`Content-Type: application/sarif+json` also marks a SARIF file). Every
format the platform's importers read is accepted: SARIF 2.1.0 from any
analyzer (CodeQL, semgrep, trivy, ...), semgrep, trivy, grype, gitleaks,
nuclei and ZAP output, an SBOM, OSV scanner results, a DefectDojo Generic
Findings export, a VEX document, and the others listed in
`docs/architecture/finding-import.md`, or a ZIP of several such files.

Already have SARIF? POST it with the token from the OIDC exchange:

```bash
curl -sf -X POST "$OPENCTEM_URL/api/v1/ci/runs/$RUN_ID/results" \
  -H "Authorization: Bearer $RUN_TOKEN" \
  -H "Content-Type: application/sarif+json" --data-binary @results.sarif
```

The same rules as for a CTIS report hold: everything is filed on the run's
repository (a repository the file names, such as SARIF
`versionControlProvenance`, is ignored), and the branch, commit and pull request come from the verified
token, never from the file. Findings the file puts on any other asset (a
host, a domain, an image, another repository) are not ingested; the response
counts them in `findings_dropped_out_of_scope`. A VEX document is stored on
the repository's matching findings only and never closes a finding. Files
are read under the same limits as a person's import (no XML entities, size,
depth and archive limits).

## 4. The verdict

After the scans `openctem-ci` asks `POST /api/v1/ci/runs/{id}/evaluate` and prints
the verdict, each blocking finding with its file and line, and links to the run
and the findings. The job exits 1 when the verdict is `fail`.

What fails is set under **Gate policy** (organization, business unit or
repository): the severity threshold, KEV, an EPSS threshold, and whether only
new findings count (the default: compared with the default branch). Committed
secrets always fail; accepted risk, false positives and suppressions are always
honored; a scanner that fails to run fails the job. **Warn** mode reports what
would fail and passes.

When a release cannot wait, **Break-glass** lets one commit pass for a limited
time with a reason; it is audited, and so is each run it lets through. Every
owner and administrator is notified in-app when it is created and each time
it is used, and so are channels subscribed to **CI Break-glass**. A burst of
refused token exchanges raises **CI Token Refusals**.

When the platform cannot decide, `--fail-on <severity>` (`fail-on` input,
`OPENCTEM_FAIL_ON` on GitLab) makes `openctem-ci` judge locally instead.

## 5. Where pipelines show up

Each workflow file of each repository that ran with OIDC appears on the
**CI/CD integration** page (Discovery > CI/CD), as a CI pipeline (the branch
never adds a row), with its runs and the repositories' coverage. A pipeline's badge
says how it ran, never "offline":

| Badge | Meaning |
|---|---|
| Running | a run started less than six hours ago and is not evaluated yet |
| Fresh | it ran within its expected cadence |
| Stale | it missed two scheduled cycles, or has been silent for three times its usual interval (7 to 30 days) |
| Failing | its last default-branch run failed the gate |
| Degraded | scanners failed in its last run, or its runner is older than the minimum supported version |
| Archived · Revoked · Never | inactive: idle for 90 days, its trust configuration was disabled or deleted, or only fork runs so far. Hidden unless you show inactive rows; nothing is deleted, and the next run brings it back |

Disabling or deleting a trust configuration revokes its pipelines and stops
the upload tokens of their running jobs at once.

## 6. No API keys in CI

CI jobs authenticate only with their OIDC identity. The former `runner` sensor
type (a sensor API key stored in CI) was removed: such sensors and their keys
were deleted on upgrade (migration `001146`) and new ones cannot be created.
Delete any `API_KEY` secret left in your CI settings. **Require OIDC for CI**
(top of **Settings > Scanning > CI/CD integration**, on for organizations created
since it exists) also refuses the key of any one-shot (standalone) sensor
(`403 ci-oidc-required`, audited).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `The CI token was not accepted` | No trust configuration admits the job, a wrong audience, or a token used twice. Owners and admins see the reason under Settings > Audit log (`ci_run.token_refused`), except for tokens that did not verify |
| `REPORT_OUT_OF_SCOPE` | The report names an asset other than the job's repository |
| Every finding counts as new | The default branch was never scanned: run the pipeline on the default branch once |
| `The CI token was not accepted` and `pipeline_identity` in the audit log | The token carries no repository/project id or no usable workflow path |
| `The CI token was not accepted` and `pipeline_cap` in the audit log | The organization has the most CI pipelines it may have; existing pipelines keep running |
| `organization_mismatch` in the audit log | The token's organization (Azure `org_id`, CircleCI `org-id`, Bitbucket `workspaceUuid`) is not the one the trust names |
| `repository_binding` in the audit log | Bitbucket: another repository of the workspace already reports under that name |
| `ssh_rerun` in the audit log | CircleCI: a re-run with SSH access, never admitted |
| `missing_claims` on CircleCI or Jenkins | No commit was reported (CircleCI), or the Jenkins claim templates `repository` and `branch` are missing |
| `403 RUNNER_OUTDATED` on the exchange | The `openctem-ci` release is older than the minimum supported version; update the pinned tag |
| `401` on upload after a long scan | The 15-minute run token expired; shorten the time between the token exchange and the verdict |
