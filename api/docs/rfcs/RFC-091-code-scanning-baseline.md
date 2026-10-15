# RFC-091: Code scanning — baseline first, then diff-aware CI, with periodic re-review

| | |
|---|---|
| Status | Accepted (2026-10-14). Phase 1 (settings, baseline state, re-baseline) implemented; phases 2–6 designed |
| Scope | api (settings, baseline state, planner, source-credential broker, ingest of full scans, gate), ctis (`source.Repository`), sdk-go (`pkg/source` fetch), sensor (code-scan jobs), web (CI/CD → Code scanning) |
| Related | RFC-051 (CI runner identity and the central gate), RFC-077 (enforced gate, PR feedback, diff-aware runs), RFC-030 / RFC-090 (distribution, work pool), RFC-040 (signed jobs, hostile results), RFC-052 (sensor grants), RFC-066 (inventory vulnerability matching), RFC-067 (scan windows), RFC-043 (finding identity) |

## 1. Summary

The platform scans each repository's **protected branches** in full before
it judges a CI run on what the run changes, and it rescans them on a schedule
and whenever its rule packs change. The protected branches are, by default,
the default branch and `develop`. CI runs on pull requests compare against
that baseline.

- A full scan runs on a **sensor**, which fetches exactly one commit read-only
  with a short-lived credential minted for that one repository.
- The results go through the same ingest and the same findings as everything
  else: per-branch occurrences, and a full-scan reconcile that marks new,
  still present and fixed.
- New CVEs for dependencies that did not change need **no rescan**: a full
  scan stores the repository's components, and inventory matching (RFC-066)
  re-matches them whenever the vulnerability feed changes.

## 2. Decisions

| # | Decision |
|---|---|
| D1 | Protected branches default to `{default}` (the repository's default branch, whatever it is named) and `develop`. A branch that does not exist is skipped. Names or `*` patterns (`release/*`), at most 20. |
| D2 | The full rescan schedule defaults to weekly, within the tenant's scan windows (RFC-067), with jitter. A per-repository override is allowed; `off` stops scheduled rescans. |
| D3 | A vulnerability feed change triggers inventory matching on the stored components (RFC-066), not a clone. A rule-pack version change triggers a rescan of the capabilities it affects, spread over 24 hours. |
| D4 | Permissions are the CI/CD area's: `scans:ci:read` to read, `scans:ci:write` to change settings or re-baseline. All changes are audited. |
| D5 | Routing: `auto` sends a repository to the tenant's own sensors. Platform-hosted sensors for public repositories need the platform fleet's claim path, which is not built yet (§6). `tenant` always uses the tenant's sensors. `platform` waits for the fleet. |
| D6 | Before a protected branch has a completed baseline, the gate treats every finding of a pull request as new (today's fail-closed `no_baseline`). The console shows "baseline pending". |

## 3. Settings

`code_scan_settings` holds one tenant template (`repository_asset_id` NULL)
and per-repository overrides. A repository uses its own row, else the
template, else the built-in defaults (D1, D2, all four capabilities, routing
`auto`, enabled).

| Field | Values |
|---|---|
| `protected_branches` | 1–20 names or patterns; `{default}` |
| `capabilities` | `sast`, `secrets`, `sca`, `iac` |
| `schedule` | `off`, `daily`, `weekly`, `monthly` |
| `routing` | `auto`, `platform`, `tenant` |
| `enabled` | a repository can be turned off |

API (all under `/api/v1/ci/code-scanning`, CI/CD module):

| Route | Permission | Notes |
|---|---|---|
| `GET /settings`, `PUT /settings` | read / write | the tenant template; `source` is `template` or `default` |
| `GET /repositories` | read | the repositories in the caller's data scope, each with effective settings, branches and baseline counts |
| `GET /repositories/{id}` | read | 404 outside the data scope |
| `PUT /repositories/{id}/settings`, `DELETE …/settings` | write | override or reset to the template; 404 outside the data scope |
| `POST /repositories/{id}/baseline` | write | sets a new baseline: queues a full scan of every known protected branch; records the default branch first; 409 when none is protected |

## 4. Baseline state

`repository_branches` gains these columns:
- `baseline_state`: `none`, `queued`, `running`, `done` or `failed`;
- `baseline_commit` and `baseline_at`: the last completed full scan;
- `baseline_error`;
- `last_full_scan_at` and `last_full_scan_trigger`: `baseline`, `schedule`, `rules`, `manual` or `stale`.

`repository_branches` has no tenant column. Every query joins the repository
asset and filters on its tenant.

## 5. Full scan flow

1. **Planner.** A job enqueues one item per repository × protected branch × trigger:
   - first sight of a repository → `baseline`;
   - `queued` from a re-baseline;
   - the schedule;
   - a rule-pack version change;
   - a protected branch head that moved without a full scan for N days → `stale`.

   Items are cut into commands of type `scan`, one per tool (semgrep, betterleaks, trivy). This keeps the existing grants, windows, slots, signer, binding and coverage reconcile unchanged. The payload carries:
   - `scanner`;
   - the target (the repository asset's name);
   - `source`, a ctis `source.Repository`: SCM kind, HTTPS clone URL, branch, exact commit, depth, credential name and capabilities.
2. **Credential broker.** The sensor holding the command's lease calls `POST /api/v2/sensor/commands/{id}/source-credential`. The platform checks that:
   - the lease epoch is current;
   - the command's tenant is the sensor's;
   - the repository asset is the tenant's;
   - the SCM installation or token is bound to the tenant.

   It then mints a token **narrowed to that one repository and read-only contents**: a GitHub App installation token with `repositories:[id]`, `contents: read`, at most 1 hour; or a GitLab project-scoped read token. The token is never stored and is audited (`code_scan.credential_issued`).
3. **Fetch.** sdk-go `pkg/source` fetches exactly the commit:
   - HTTPS only, to an SSRF-checked address pinned for git, with no redirects;
   - no hooks, submodules, filters or inherited configuration;
   - symlinks as plain files;
   - `fsck` on every object, and the commit verified;
   - bounded in time and in size.

   The token reaches git only as a URL-scoped header in git's environment, never a scanner's.
4. **Scan.** The scanners run on the checkout with the platform's configuration: repository scanner config and ignore files are not read (as in the CI runner). The sensor then removes the checkout.
5. **Results.**
   - **Report.** Each report carries `coverage_type: full`, the branch (`is_default_branch` from the platform's branch row) and the commit.
   - **Reconcile.** Ingest records per-branch occurrences. The full-scan reconcile marks findings not seen by that tool on that branch `auto_fixed` (`not_seen_in_scan`).
   - **Components.** The sca report's components become the repository's software inventory, which inventory matching keeps current as the feed changes.
   - **Baseline state.** On success: `baseline_state = done`, with `baseline_commit` and `baseline_at`. On failure: `failed` and `baseline_error`.
6. **Gate.** A pull request whose target branch has `baseline_state = done` is compared with that branch (RFC-077 base-branch baseline). Diff runs never resolve findings.

## 6. Not in this RFC (yet)

- **The platform-hosted fleet.** A platform sensor serving many tenants: the claim path for platform jobs exists in the queue repository but has no route, and results require the command's tenant to equal the sensor's. Until it exists, `auto` routes to the tenant's sensors only.
- Scanning full git history for secrets on every rescan. Planned instead: once on the baseline (bounded), then commit ranges.
- Platform scans of pull-request heads. CI does PR gating with the developer's own compute.

## 7. Security

| Threat | Control |
|---|---|
| Clone credential leak | Minted at execution time for the lease holder only; one repository, read-only, ≤ 1 h; never stored or in the job; git's environment only; audited |
| Cross-tenant fetch or write | The broker checks that the command, sensor, repository asset and SCM binding share one tenant; the ingest binding limits writes to the command's repository asset |
| Malicious repository content | `pkg/source` hardening (§5.3); workspace confinement on the sensor |
| Scanner config in the repository hides findings | Not read; the platform's rule packs, pinned by version |
| Forked pull requests | Full scans fetch only protected branches of the repository itself; CI forks stay scan-only |
| Rescan storms | Fair share, jitter on rule-pack triggers, scan windows, a per-tenant re-baseline rate limit |
| Settings tampering | `scans:ci:write`; data scope on per-repository routes; audit of every change |
| Scanning a repository the organization does not own | The planner scans a repository only when a repository scope entry covers it and no exclusion matches (RFC-054 §17), and only with a credential minted from the organization's own code-host connection; a CI trust alone never yields a clone |

## 8. Phases

| Phase | Content | State |
|---|---|---|
| 1 | Settings, baseline state, re-baseline API | Implemented |
| 2 | ctis `source.Repository`; sdk-go `pkg/source` | In review |
| 3 | Planner, credential broker, `code_scan` ingest (full-scan reconcile, components), baseline transitions | Designed |
| 4 | Sensor: code-scan jobs through `pkg/source` | Designed |
| 5 | Console: CI/CD → Code scanning (status table, re-baseline, settings, template) | Designed |
| 6 | Gate reads `baseline_state`; triggers for rule packs and stale heads | Designed |
