# Run OpenCTEM security scans in GitLab CI/CD

This guide connects a GitLab project (gitlab.com or self-managed) to OpenCTEM so
every merge request and default-branch pipeline is scanned, results land in
OpenCTEM, and the pipeline passes or fails on your organization's gate.

**No secret is stored in GitLab.** The job proves who it is with the ID token
GitLab issues for it (OIDC), exchanges it for a run token that lives at most
15 minutes and is valid for that one run of that one project, and uploads only
scan results. Source code never leaves the runner. Background:
[CI runner identity](../architecture/ci-runner-identity.md),
[RFC-051](../rfcs/RFC-051-ci-runner-identity-and-gate.md). GitHub Actions and
the shared concepts: [Connect CI pipelines](connect-ci-pipelines.md).

## What you need

- OpenCTEM: the `scans:ci:write` permission (owners and administrators).
- GitLab 15.7 or later (`id_tokens` in `.gitlab-ci.yml`).
- A GitLab runner with the Docker executor (or Kubernetes) that can pull
  `ghcr.io/openctemio/sensor:*` images and reach your OpenCTEM API over HTTPS.
- Self-managed GitLab only: the OpenCTEM API must reach your GitLab's
  `/oauth/discovery/keys` over HTTPS to verify tokens (see
  [Self-managed GitLab](#self-managed-gitlab)).

## 1. Trust the GitLab project in OpenCTEM

**Settings > Scanning > CI pipelines > Trust > Add trust**:

| Field | What to enter |
|---|---|
| Provider | **GitLab CI** |
| Issuer | `https://gitlab.com`, or your GitLab URL for self-managed |
| Owners | your group path, e.g. `acme` (admits every project of the group) |
| Repositories | or specific projects: `acme/api, acme/web`; `acme/*` one level, `acme/**` any depth |
| Branches and tags | optional, e.g. `main, release/*` (a merge request matches on its source branch) |
| Environments / Events | optional: require a deployment environment or limit pipeline sources |
| Admit fork merge requests | leave **off** |
| Default branch | the baseline branch, usually `main` |

Save. The page shows your **organization ID** and a ready `.gitlab-ci.yml`
snippet whose `aud` (audience) is `openctem:tenant:<organization ID>`. Keep the
page open for step 3.

The same through the API:

```bash
curl -X POST "$API_URL/api/v1/ci/trust-configs" \
  -H "Authorization: Bearer $SESSION" -H 'Content-Type: application/json' \
  -d '{"name":"acme on GitLab","provider":"gitlab","issuer":"https://gitlab.com",
       "rules":{"owners":["acme"],"refs":["main","release/*"]}}'
```

## 2. Add two CI/CD variables in GitLab

**Project (or group) > Settings > CI/CD > Variables**:

| Key | Value | Notes |
|---|---|---|
| `API_URL` | `https://openctem.example.com` | your OpenCTEM URL |
| `OPENCTEM_TENANT_ID` | the organization ID from step 1 | not a secret |

Do **not** add an `API_KEY`: the ID token replaces it.

## 3. Add the job to `.gitlab-ci.yml`

### Option A: the template (recommended, parallel per-tool jobs)

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/openctemio/sensor/main/ci/gitlab/openctem-security.yml'

stages:
  - security

sast:        # semgrep
  extends: .openctem-sast
secrets:     # betterleaks
  extends: .openctem-secrets
sca:         # trivy (dependencies)
  extends: .openctem-sca
```

Pin the template to a release tag instead of `main`, and review it before
including it: it runs in your pipeline with your project's identity. The
template runs each sensor image by digest; see **Security notes** for how
those digests are checked and updated.

Optional extra jobs from the same template: `.openctem-iac` (trivy config),
`.openctem-container` (scan the image you just built, default branch),
`.openctem-dast` (nuclei against a deployed URL, in a stage after deploy).

### Option B: one job, no include

```yaml
openctem-security:
  stage: test
  image:
    # A release pinned by digest, never a moving tag (see Security notes).
    name: ghcr.io/openctemio/sensor:v0.9.1-ci@sha256:97f5512165d2c79240bb01f4cdbc710b85b1517cca95d4015aa39d35c60017e1
    entrypoint: [""]
  id_tokens:
    OPENCTEM_ID_TOKEN:
      aud: "openctem:tenant:$OPENCTEM_TENANT_ID"
  variables:
    # The image runs as uid 1001; trust exactly this job's checkout for git.
    GIT_CONFIG_COUNT: "1"
    GIT_CONFIG_KEY_0: safe.directory
    GIT_CONFIG_VALUE_0: $CI_PROJECT_DIR
  script:
    - openctemio-sensor -tools semgrep,betterleaks,trivy -target . -auto-ci -push
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

What the job does: runs the scanners on the checkout, converts their output to
CTIS on the runner, exchanges `OPENCTEM_ID_TOKEN` for a run token, uploads the
results, asks the platform for the verdict, prints it with each blocking
finding (file, line, link), and exits `1` when the verdict is `fail`.

## 4. Make the gate block merges

- The template marks exit code `1` as `allow_failure` so a first rollout does
  not block anyone. To **enforce** the gate, override it:
  ```yaml
  sast:
    extends: .openctem-sast
    allow_failure: false
  ```
- Then turn on **Settings > Merge requests > Pipelines must succeed**.
- What fails is set in OpenCTEM under **Settings > Scanning > CI pipelines >
  Gate policy** (organization, business unit or repository): severity threshold,
  KEV, EPSS, and whether only **new** findings count (default: compared with the
  default branch). Committed secrets always fail; accepted risk, false positives
  and suppressions never do. **Warn** mode reports what would fail and passes.
- When a release cannot wait, **Break-glass** lets one commit pass for a limited
  time with a reason. It is audited, and so is every run it lets through.
- When OpenCTEM cannot be reached, `-fail-on <severity>` makes the job decide
  locally instead of failing open.

## 5. Run it once on the default branch

The "new findings only" gate compares a merge request with the default branch.
Until the default branch has been scanned once, every finding counts as new, so
run the pipeline on `main` first (push, or **Build > Pipelines > Run pipeline**).

## 6. Check it in OpenCTEM

- **Sensors** page, mode **Runner**: one row per project and workflow file
  (branches never add rows), with its last run, gate result and sensor version.
  A pipeline is shown as Running, Fresh, Stale, Failing or Degraded, never
  "offline".
- Open the row for its runs, branches and gate trend; findings appear on the
  project's repository asset.
- **Coverage** (CI pipelines): which repositories have fresh SAST, SCA and
  secret scanning, and which have none.

## Self-managed GitLab

- Enter your GitLab URL as the **Issuer** in step 1 (for example
  `https://gitlab.acme.internal`). It must match the `iss` claim exactly.
- OpenCTEM fetches your GitLab's signing keys over HTTPS through its
  outbound-request guard. A GitLab on a private address needs its subnet in
  `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS` on the OpenCTEM API (for example
  `10.20.0.0/16`).
- The certificate must be trusted by the API (a public CA, or your CA added to
  the API container).
- A custom audience in the trust configuration replaces
  `openctem:tenant:<id>`; set the same value in `id_tokens`.

## Security notes

- Nothing reusable is stored in GitLab. Each ID token can be exchanged once,
  and the run token expires after 15 minutes.
- A run can only report on its own project. Branch, commit and merge request
  are taken from the verified token, not from the uploaded report.
- Fork merge requests run in the fork's project by default and do not match
  your rules. If you run them in the parent project, keep **Admit fork merge
  requests** off, or restrict the configuration to protected branches and tags.
- Disabling or deleting the trust configuration stops new uploads at once,
  including jobs that are running.
- **Protected refs only.** Turn on **Protected branches and tags only** in the
  trust configuration so that only pipelines on protected branches and tags
  (GitLab's `ref_protected` claim) get a token: a developer who can push an
  unprotected branch cannot then send results as the project.
- **Least privilege of the run token.** The token the job receives works only
  for its own run's results, baseline comparison and verdict. It cannot read
  findings or assets, call any other API, or act on another run; it expires
  after 15 minutes and is renewed only for the same job.
- **Budgets.** A run accepts at most 200 reports, and a pipeline may start at
  most 300 runs an hour; beyond that the exchange is refused and audited.
- **Secrets in results.** The sensor masks a secret before it leaves the job,
  and the platform stores only a short masked preview and a keyed fingerprint,
  never the value, whatever the upload contains.
- **Pin the image by digest and verify it.** A tag such as `latest-ci` can be
  moved; a digest cannot. The sensor's images are signed with cosign (keyless,
  by the sensor repository's release workflow). Check a digest before you pin
  it (cosign v3):

  ```bash
  cosign verify ghcr.io/openctemio/sensor@sha256:<digest> \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/openctemio/sensor/\.github/workflows/docker-publish\.yml@refs/tags/v'
  ```

  On a new sensor release, the sensor repository's `scripts/pin-ci-images.sh
  vX.Y.Z` resolves, verifies and re-pins the templates; update a copied job
  the same way.
- **Minimum runner version.** A runner older than the platform's minimum
  supported sensor version is refused (`403 RUNNER_OUTDATED`): update the
  pinned image.
- **Enforce the gate.** The template starts in rollout mode (a failing gate
  does not fail the pipeline). Once findings are triaged, set
  `allow_failure: false` (step 4) so a failing verdict blocks the merge.
- **Audit.** Every exchange (admitted or refused, with the reason), upload,
  verdict and break-glass is in **Settings > Audit log**; administrators are
  notified of each break-glass and of bursts of refused tokens.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `The CI token was not accepted` | No trust configuration admits the project or branch, the `aud` differs from the configuration's audience, or the token was used twice. The reason is in **Settings > Audit log** (`ci_run.token_refused`) |
| `id_tokens` is ignored / `OPENCTEM_ID_TOKEN` is empty | GitLab older than 15.7, or the variable name differs from the one under `id_tokens` |
| `fatal: detected dubious ownership` | The job lacks the `GIT_CONFIG_*` safe.directory variables shown above |
| `403 RUNNER_OUTDATED` on the exchange | The pinned sensor image is older than the minimum supported version: re-pin a current release |
| `401` on upload after a long scan | The 15-minute run token expired: the sensor exchanges the token at the first upload, so keep the upload and the verdict within 15 minutes of each other (split slow scanners into parallel jobs) |
| `REPORT_OUT_OF_SCOPE` | The report names an asset other than this project's repository |
| Every finding is "new" | The default branch was never scanned: see step 5 |
| Push disabled, "scan-only mode" in the log | `OPENCTEM_TENANT_ID` is not set in the job |
| Self-managed: token refused with an issuer or key error | The Issuer URL does not match `iss`, or the API cannot reach your GitLab's keys (private address flag, certificate) |

## No API keys in CI

CI jobs authenticate only with their ID token. Runner sensors (a sensor API key
stored in CI) were removed, with their keys, on upgrade. If a pipeline still
sets `API_KEY`, add the trust configuration and the `id_tokens` block, then
delete the variable.
