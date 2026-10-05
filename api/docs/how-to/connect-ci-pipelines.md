# Connect CI pipelines without a stored secret

GitHub Actions and GitLab CI jobs can send scan results and fail on the
platform's gate using the identity their CI provider gives them (OIDC). Nothing
secret is stored in CI. Design: [RFC-051](../rfcs/RFC-051-ci-runner-identity-and-gate.md).

You need `scans:ci:write` (owners and administrators).

## 1. Add CI trust

**Settings > Scanning > CI pipelines > Trust > Add trust**:

- **Provider**: GitHub Actions or GitLab CI. For a self-managed GitLab, enter
  its URL as the issuer. The platform fetches its keys over HTTPS through the
  outbound-request guard; an instance on a private address needs
  `OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1` on the API.
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
        uses: docker://ghcr.io/openctemio/sensor:latest-ci
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
  image: ghcr.io/openctemio/sensor:latest-ci
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
**Sensors** page in **Runner** mode, as a CI pipeline (the branch never adds a
row). Its badge says how it ran, never "offline":

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

## 6. Moving off API keys

A runner sensor's API key still works unless the organization requires OIDC
for CI; its responses carry a `Deprecation` header and the sensor prints a
warning. Once the pipeline runs with OIDC, delete the `API_KEY` secret from CI,
revoke the runner sensor's key, and turn on **Require OIDC for CI** at the top
of **Settings > Scanning > CI pipelines**: a CI sensor's key is then refused
(`403 ci-oidc-required`) and each refusal is audited. Organizations created
since this setting exists have it on from the start.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `The CI token was not accepted` | No trust configuration admits the job, a wrong audience, or a token used twice. Owners and admins see the reason under Settings > Audit log (`ci_run.token_refused`), except for tokens that did not verify |
| `REPORT_OUT_OF_SCOPE` | The report names an asset other than the job's repository |
| Every finding counts as new | The default branch was never scanned: run the pipeline on the default branch once |
| `The CI token was not accepted` and `pipeline_identity` in the audit log | The token carries no repository/project id or no usable workflow path |
| `The CI token was not accepted` and `pipeline_cap` in the audit log | The organization has the most CI pipelines it may have; existing pipelines keep running |
| `401` on upload after a long scan | The 15-minute run token expired; on GitHub the sensor renews it, on GitLab shorten the time between the first upload and the verdict |
