# Finding retest checks

> A person on the security team attaches a **retest check** to a finding that
> has no check of its own (a pentest-style web finding, a manual or bug-bounty
> finding, a DAST finding without a template), so that "Retest now" and proof
> of fix re-run it on a sensor. Builds on [continuous retest](continuous-retest.md)
> (RFC-039), the tenant template library (`scanner_templates`) and
> [job signing](job-signing.md).

## Model

A check is a link from one finding to one **template of the organization's
template library**, plus two pieces of state the platform owns:

| Field | Meaning |
|---|---|
| `template_id` | the nuclei template that runs (versioned by content digest, approved for sensors as the organization's policy says, signed on delivery) |
| `kind` | `nuclei` (written or picked from the library) or `http_assertion` (a declarative request + matchers, compiled to a nuclei template by the platform) |
| `owns_template` | the template was created for this check; editing the check edits it, removing the check deletes it when nothing else uses it. A library template picked for a finding is never edited from the finding |
| `tier`, `tier_reason` | T0 / T1 / T2 from the content-pack classifier; T2 = state-changing, out-of-band or high-volume |
| `approved_digest`, `approved_by` | a second person's approval of an intrusive (T2) check, bound to the exact content digest |
| `calibrated_digest`, `calibrated_at` | the content digest that **matched the finding once** |
| `author_id` | who wrote the current version (cannot approve it) |

Table `finding_retest_checks`, one row per finding (`UNIQUE (tenant_id,
finding_id)`); composite foreign keys `(finding_id, tenant_id)` and
`(template_id, tenant_id)` so a check never links another tenant's finding or
template; a template in use cannot be deleted from the library (`409
TEMPLATE_IN_USE`). Retest rows record `retest_check_id`, `check_digest` and
`check_path` (provenance of every attempt).

## Validation (every save and every dispatch)

1. The template library's validator (`template.ValidateTemplate`): code,
   javascript, flow, headless, file and self-contained templates are refused on
   the parsed document; regex safety.
2. Retest check rules (`internal/app/retestcheck/rules.go`), because a check
   runs against one finding's own target:
   - HTTP requests only (`http` / `requests`); other protocols and workflows are refused;
   - every `path` is `{{BaseURL}}` or `{{RootURL}}` followed by `/` or `?` (no
     host suffix, user info, port or protocol-relative tail);
   - raw requests name a path, never an absolute URL, and `Host: {{Hostname}}`;
   - no `redirects` (any host), `unsafe` raw requests or `fuzzing`;
   - no out-of-band callbacks (interactsh, public OOB hosts);
   - no credentials: `Authorization`, `Cookie`, API-key headers and
     credential-shaped literals are refused.
3. Tier from the content-pack classifier.

The HTTP assertion is validated field by field (method GET/HEAD/POST/OPTIONS,
path starting with `/`, header names, no credential or `Host` header, no
`{{ }}` expressions anywhere, at most 10 matchers, valid regexes) and compiled
with a YAML encoder, never by string concatenation.

`POST /findings/{id}/retest-check/test` runs all of it without saving and
returns the template that would run.

## Running a check

`internal/app/retest`: when a finding has a check, `eligible` takes the
check's template id as the rule, whatever tool and rule the finding was
reported with; the asset, target and active-probe gate rules are unchanged
(the target is always the server-computed origin of the finding's asset).
Before anything is recorded the retest is refused when:

- the check's current version is T2 and not approved by a second person;
- its template is not an active nuclei template or no longer passes validation;
- its template version awaits approval for sensors (organizations with a job
  signer and a template approval count);
- no online organization sensor reports both `retest:nuclei` and
  `retest-templates:nuclei` (`ErrNoCheckSensor`: older sensors and shared
  sensors never receive a custom check).

The retest command carries the template the way scan commands do:

```json
{"scanner": "nuclei", "targets": ["https://shop.example.com"],
 "items": [{"ref": "<finding>", "target": "https://shop.example.com", "kind": "finding",
            "rule_id": "retest-check-0f0e0d0c0000", "template": "<template id>"}],
 "custom_templates": [{"id": "<template id>", "name": "retest-check-….yaml",
                       "template_type": "nuclei", "content": "<base64>"}],
 "required_capabilities": ["retest:nuclei", "retest-templates:nuclei"]}
```

On delivery the platform signs the custom templates (per-tenant envelope) and
the signed job statement lists their digests; the job signer accepts only
digests in its ledger. The sensor verifies the digest (or the envelope), checks
the content again, and runs the template against the target.

## Verdicts

| Sensor verdict | Check calibrated for the digest sent? | Outcome (`reason_code`) |
|---|---|---|
| match, digest = sent | — | `still_vulnerable` (`matched`); the check becomes calibrated for that digest |
| no match on the answered endpoint (`check_path`), digest = sent | yes | `confirmed_fixed` (`not_matched`) |
| no match, digest = sent | no | `not_reproduced` (`check_uncalibrated`) |
| any conclusive verdict for another digest | — | `inconclusive` (`template_changed`) |
| unverifiable, failed, no result | — | `inconclusive` |

A check proves a fix only after it reproduced the issue once: a check that can
never match cannot close a finding. Editing the content resets approval and
calibration. The rest follows [continuous retest](continuous-retest.md)
(auto-resolve setting, regression reopen, evidence kept, cooldown and caps).

## API

| Route | Permission |
|---|---|
| `GET /api/v1/findings/{id}/retest-check` | `findings:read` |
| `POST /api/v1/findings/{id}/retest-check/test` | `findings:retest_checks:write` |
| `PUT /api/v1/findings/{id}/retest-check` | `findings:retest_checks:write` |
| `DELETE /api/v1/findings/{id}/retest-check` | `findings:retest_checks:write` |
| `POST /api/v1/findings/{id}/retest-check/approve` | `scope:approve` + recent sign-in |

All routes sit under `/findings/{id}/**`, so the finding data-scope guard
applies (out of scope = 404). The tenant comes from the token. Save, remove and
approve are audited (`finding.retest_check_saved`, `…_removed`, `…_approved`)
with the template, digest, kind and tier. `findings:retest_checks:write` is
held by owner and admin and by the Security analyst, Vulnerability manager,
AppSec engineer and Validation engineer role templates.
Retest history entries carry `retest_check_id` and `check_digest`.

## Threat model

| Threat | Control |
|---|---|
| Run code on a sensor | validator refuses code-class templates; the sensor checks content again; the digest is signed |
| Point a check at a third party | server-computed target; target-bound rules; active-probe gate; sensor web scope and forwarder; no OOB |
| Intrusive or high-volume check | T2 needs a second person's approval (step-up), bound to the digest; request-volume cap of the validator |
| Close a finding with a check that never matches | calibration rule; provenance on every attempt; the risk-tier resolve gate still applies |
| Edit after approval or calibration | both are bound to the digest and reset on change; the signer ledger needs the new digest |
| Cross-tenant use | tenant-scoped queries, composite foreign keys, per-tenant ledger; 404 |
| Out-of-scope finding | `/findings/{id}/**` data-scope guard; 404 |
| Secrets in a check | credential headers and credential-shaped literals refused |
| Parse failure read as fixed | the sensor load-checks the template; any error is inconclusive |
| Shared sensor runs tenant content | routing needs an organization sensor; the signer refuses templates for shared sensors |

## Code

| Piece | Where |
|---|---|
| Domain (check, assertion, compile) | `pkg/domain/retestcheck` |
| Rules, service, adapters | `internal/app/retestcheck` |
| Retest integration | `internal/app/retest/service.go` (`CheckSource`, `methodFor`, `applyCheck`), `pkg/domain/retest` (`ApplyCheckCalibration`) |
| Command payload | `internal/app/validation/retest_command.go` (`custom_templates`, item `template`, `retest-templates:<tool>`) |
| Store | `internal/infra/postgres/finding_retest_check_repository.go`, migration `finding_retest_checks` |
| HTTP | `internal/infra/http/handler/finding_retest_check_handler.go`, `routes/finding_retest.go` |

## Later

Credential references resolved on the sensor (authenticated checks), opengrep
rules for repository findings ("rescan to verify with this rule"), attaching one
check to every matching finding, an AI-drafted check reviewed by a person, a
bridge to the pentest retest workflow, TLS checks addressed by `{{Hostname}}`.
