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
  address needs `OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1` on the API.
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

## 2. GitHub Actions

```yaml
permissions:
  contents: read
  id-token: write # lets the job request its OIDC token

jobs:
  openctem:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: OpenCTEM security scan
        # A release pinned by digest, never a moving tag (verify it with cosign;
        # see the GitLab guide's Security notes).
        uses: docker://ghcr.io/openctemio/sensor:v0.9.1-ci@sha256:97f5512165d2c79240bb01f4cdbc710b85b1517cca95d4015aa39d35c60017e1
        with:
          args: -tools semgrep,betterleaks,trivy -target . -auto-ci -push
        env:
          API_URL: https://openctem.example.com
          OPENCTEM_TENANT_ID: <your organization id>
          # OPENCTEM_OIDC_AUDIENCE: only if the trust configuration uses a custom audience
```

`id-token: write` is required; without it GitHub gives the job no token and the
sensor falls back to `API_KEY` if one is set. Pull requests from forks get no
token from GitHub on `pull_request`; that is intended.

## 3. GitLab CI

Step-by-step GitLab guide (variables, templates, enforcing the gate, self-managed GitLab, troubleshooting): [Run OpenCTEM security scans in GitLab CI/CD](gitlab-ci.md).

```yaml
openctem-security:
  image: ghcr.io/openctemio/sensor:v0.9.1-ci@sha256:97f5512165d2c79240bb01f4cdbc710b85b1517cca95d4015aa39d35c60017e1
  id_tokens:
    OPENCTEM_ID_TOKEN:
      aud: openctem:tenant:<your organization id>
  variables:
    API_URL: https://openctem.example.com
    OPENCTEM_TENANT_ID: <your organization id>
  script:
    - openctemio-sensor -tools semgrep,betterleaks,trivy -target . -auto-ci -push
```

The `aud` must equal the trust configuration's audience. A GitLab ID token can
be exchanged once, so the sensor exchanges it at the first upload, after the
scans; keep the upload and the verdict within 15 minutes of that.

Merge requests from forks run in the fork's project by default, whose path does
not match your rules. If you run them in the parent project, turn on
**Protected branches and tags only** for configurations that must not admit
them.

## 3a. Azure Pipelines

**Trust:** provider **Azure Pipelines**, the organization's **id** (a UUID:
Organization settings > Microsoft Entra, or the `org_id` of a sample token).
The issuer is `https://vstoken.dev.azure.com/<organization id>`.

The job asks Azure DevOps for a *pipeline* token (no service connection):
`openctem-ci` calls `$(System.OidcRequestUri)` with the job's access token,
which the step must map in:

```yaml
- script: openctem-ci scan --capability sast --aggregate
  env:
    SYSTEM_ACCESSTOKEN: $(System.AccessToken)
    OPENCTEM_API_URL: https://openctem.example.com
    OPENCTEM_TENANT_ID: <your organization id>
```

The token signs the repository (`rpo_uri`), commit (`rpo_ver`), ref
(`rpo_ref`), project (`prj_id`), pipeline definition (`def_id`) and run
(`run_id`). Rules match the repository path: `acme/api` for a GitHub
repository, `<organization>/<project>/<repository>` for Azure Repos.

- Its audience is always `api://AzureADTokenExchange` and cannot be changed,
  so the same token is valid for any service that trusts your organization's
  pipeline tokens. The platform pins the token to your organization
  (`org_id` must match the issuer), accepts each token once, and Azure
  tokens live five minutes.
- The token cannot tell a fork's pull request from your own: every pull
  request build is refused unless **Admit fork pull requests** is on. Builds
  of fork pull requests in Azure Pipelines do not get your secrets by
  default; turn it on only if your pipeline never builds fork code.
- **Events**, **Environments** and **Protected branches and tags only** are
  not available: the token carries none of them. List the refs instead.

## 3b. Bitbucket Pipelines

**Trust:** provider **Bitbucket Pipelines**, the **workspace** (its slug, as
in `bitbucket.org/<workspace>`) and the **workspace UUID** (Workspace
settings, or `workspaceUuid` in a sample token). The issuer is
`https://api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc`.
The UUID is required: a renamed workspace gives up its slug, and the UUID is
what keeps a later owner of that slug out.

```yaml
options:
  oidc:
    audiences:
      - openctem:tenant:<your organization id>
pipelines:
  default:
    - step:
        oidc: true
        script:
          - openctem-ci scan --capability sast --aggregate
```

`openctem-ci` reads `BITBUCKET_STEP_OIDC_TOKEN` and reports the repository
name (`BITBUCKET_REPO_FULL_NAME`) and commit (`BITBUCKET_COMMIT`).

- The token signs the repository's **UUID**, not its name. **Repositories**
  rules therefore list repository UUIDs; **Owners** names the workspace. The
  name a job reports is bound to the UUID that first used it: another
  repository of the workspace cannot later report under that name (refused,
  `repository_binding` in the audit log).
- The audience must contain your organization id (the default
  `openctem:tenant:<id>`): the workspace's own audience is shared by every
  service that trusts the workspace.
- **Environments** are deployment environment UUIDs; **Protected branches
  and tags only** needs them (environments whose deployment rules admit only
  protected branches). **Events** are not available.

## 3c. CircleCI

**Trust:** provider **CircleCI**, the organization's **id** (Organization
settings > Overview). The issuer is
`https://oidc.circleci.com/org/<organization id>`.

CircleCI's ready-made `CIRCLE_OIDC_TOKEN` has the organization id as its
audience, which any service trusting your organization shares; the platform
refuses it. Mint one for the platform in the step:

```yaml
- run: |
    export OPENCTEM_ID_TOKEN="$(circleci run oidc get --claims '{"aud":"openctem:tenant:<your organization id>"}')"
    openctem-ci scan --capability sast --aggregate
```

- The token signs the repository (`vcs-origin`), ref (`vcs-ref`), project,
  workflow and job, **not the commit**. `openctem-ci` reports
  `CIRCLE_SHA1`; the run marks its commit unverified, and a break-glass
  (granted per commit) never applies to such a run.
- A job re-run with SSH is always refused. Pull request refs are refused
  unless **Admit fork pull requests** is on (the token cannot tell a fork's).
- **Events**, **Environments** and **Protected branches and tags only** are
  not available.

## 3d. Jenkins

Jenkins has no OIDC of its own; install the **OpenID Connect Provider**
plugin. It signs tokens with a key per credential and publishes the keys at
`<Jenkins URL>/oidc` (or a folder's issuer). A controller the platform
cannot reach sets the credential's **issuer URI** to a static HTTPS location
and publishes the two files Jenkins shows there
(`.well-known/openid-configuration` and `jwks`).

1. Manage Jenkins > Security > OpenID Connect: add the **claim templates**
   the platform reads (they apply to every token of the controller):

   | Claim | Template | Required |
   |---|---|---|
   | `repository` | `${GIT_URL}` | yes |
   | `branch` | `${BRANCH_NAME}` (multibranch) or `${GIT_BRANCH}` | yes |
   | `sha` | `${GIT_COMMIT}` | recommended (otherwise the job's report, unverified) |

2. Add an **OpenID Connect id token** credential (folder-scoped for the jobs
   that scan) with the audience `openctem:tenant:<your organization id>`.
3. **Trust:** provider **Jenkins**, the credential's issuer.
4. In the pipeline:

```groovy
withCredentials([string(credentialsId: 'openctem-oidc', variable: 'OPENCTEM_ID_TOKEN')]) {
  sh 'openctem-ci scan --capability sast --aggregate'
}
```

- The pipeline is the job (its URL, without the branch of a multibranch
  job), the run the build number. The claims prove what your controller
  asserts: anyone who can change the controller's configuration or its
  credentials can mint any of them. Scope the credential to the folders whose
  jobs may report.
- Multibranch pull request builds (`PR-<n>`) are refused unless **Admit fork
  pull requests** is on.
- The plugin sends no `jti`; the platform accepts each token once by its
  hash. Re-saving the credential rotates its key at once: republish the
  static keys if you use an issuer URI.
- No fallback secret: a long-lived CI credential would be an API key by
  another name. A controller that cannot run the plugin uses scan-only mode.

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

After the scans the sensor asks `POST /api/v1/ci/runs/{id}/evaluate` and prints
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

When the platform cannot be reached, `-fail-on <severity>` makes the sensor
judge locally instead.

## 5. Where pipelines show up

Each workflow file of each repository that ran with OIDC appears on the
**CI/CD integration** page (Discovery > CI/CD), as a CI pipeline (the branch
never adds a row), with its runs and the repositories' coverage. The Sensors
page lists the sensors in your networks and links to it. A pipeline's badge
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
(top of **Settings > Scanning > CI pipelines**, on for organizations created
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
| `403 RUNNER_OUTDATED` on the exchange | The sensor image is older than the minimum supported version; update the pinned image |
| `401` on upload after a long scan | The 15-minute run token expired; on GitHub the sensor renews it, on GitLab shorten the time between the first upload and the verdict |
