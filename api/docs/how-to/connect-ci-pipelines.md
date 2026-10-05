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
time with a reason; it is audited, and so is each run it lets through.

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

A runner sensor's API key still works; its responses carry a `Deprecation`
header and the sensor prints a warning. Once the pipeline runs with OIDC,
delete the `API_KEY` secret from CI and revoke the runner sensor's key.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `The CI token was not accepted` | No trust configuration admits the job, a wrong audience, or a token used twice. Owners and admins see the reason under Settings > Audit log (`ci_run.token_refused`), except for tokens that did not verify |
| `REPORT_OUT_OF_SCOPE` | The report names an asset other than the job's repository |
| Every finding counts as new | The default branch was never scanned: run the pipeline on the default branch once |
| `The CI token was not accepted` and `pipeline_identity` in the audit log | The token carries no repository/project id or no usable workflow path |
| `The CI token was not accepted` and `pipeline_cap` in the audit log | The organization has the most CI pipelines it may have; existing pipelines keep running |
| `401` on upload after a long scan | The 15-minute run token expired; on GitHub the sensor renews it, on GitLab shorten the time between the first upload and the verdict |
