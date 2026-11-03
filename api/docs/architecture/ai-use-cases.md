# AI use cases

Code: `pkg/domain/aianalysis/use_case_settings.go`, `internal/app/tenantai/use_cases.go`,
`internal/infra/postgres/tenant_ai_use_cases.go`, `internal/infra/http/handler/ai_use_cases_handler.go`,
enforcement in `internal/app/aianalysis/builtin.go` and `internal/app/aitriage/use_case.go`,
migration `ai_use_cases`. Related: [AI agents](ai-analysis.md), [AI triage](ai-triage.md),
[AI context masking](ai-context-masking.md).

An organization decides, for each kind of AI result, whether it waits for a person or applies on its
own, and how much data the AI may see. The settings sit with the organization's other AI settings
(`tenant_ai_settings.use_cases`, one JSON object keyed by use case); there is no separate store.

## Use cases

| Use case | Produced by | Results |
|---|---|---|
| `triage` | AI triage, and the `triage.v1` kind of AI agents | verdict (true positive, likely false positive, needs information), severity |
| `remediation` | the `remediation.v1` kind | remediation steps |
| `summary` | the `summary.v1` kind | a short summary |

## Settings per use case

| Setting | Values | Default |
|---|---|---|
| `mode` | `off`, `suggest`, `auto_apply` | `suggest` |
| `ceiling` (most sensitive data sent) | `public`, `internal`, `restricted` | `internal` |
| `min_confidence` (to apply on its own) | 0.50 to 0.99 | 0.85 |

Nothing runs while AI is turned off for the organization (consent, [AI triage](ai-triage.md)):
every use case is then off in force (`effective_mode`), whatever its saved mode. A stored value that
does not read is replaced by the default (fail closed); an unreadable row refuses the run.

### What each mode does

- **off**: the use case does not run. The built-in executor records the run as refused with
  `use_case_off` before any model call; AI triage refuses a request (`AI_USE_CASE_OFF`), bulk and
  automatic triage, and fails a row already queued with `ai_use_case_off`.
- **suggest**: nothing changes the finding and nothing is filed. An AI agent writes its result as its
  own internal comment (reason `suggest_mode`); AI triage keeps the result card. A person acts on it.
- **auto_apply**: a clean result at or above `min_confidence` that only adds information applies:
  a verdict that confirms a new finding (status `confirmed`), summary and remediation steps.

Fixed rules, not settings (the same in every mode):

- A severity never changes without a person. A raise stays a suggestion (`severity_needs_person`);
  a downgrade becomes a severity request a person decides.
- A risk-lowering change becomes a request a person decides: a likely-false-positive verdict files a
  false-positive approval request with the AI as requester (AI agents: their own identity; AI triage:
  the `ai_triage` actor, medium and low findings only, likelihood at least 0.9).
- A result with review reasons (no or unresolved evidence, unknown placeholder, injection markers in
  the input, coerced output) or under 0.5 confidence is never applied.
- A run a person started never files a risk-lowering request (that person could approve it).
- The AI agent's own preset and permissions still bound what it may do: the use case can only narrow.

### Data class ceiling

The fields sent are those at or below the lower of the use case's ceiling and, for an AI agent, its
own `data_class_ceiling` (`aipolicy` is the one field registry):

| Class | Fields |
|---|---|
| public | CVE, CWE, OWASP, KEV, EPSS |
| internal | also title, description, severity, CVSS, source, tool, file and line, exposure, data exposure, compliance, priority, asset name, type, criticality, environment, exposure |
| restricted | also the code snippet |
| tenant only | anything unregistered: never sent |

Withheld fields are recorded on the run (`fields_withheld`, shown in the Why view). A leaked-secret
finding never sends its snippet, whatever the ceiling; its description goes through the secret
redactor. When nothing is within the ceiling, AI triage fails with `nothing_to_send` and no call is made.
The organization's AI egress policy (pentest TLP, campaign opt-out) and masking apply on top.

## Who may change it

| Route | Gate |
|---|---|
| `GET /api/v1/organization/settings/ai/use-cases` | `settings:read` (every built-in role) |
| `PUT /api/v1/organization/settings/ai/use-cases/{use_case}` | owner or administrator with `settings:write` |

A **loosening** needs a recent sign-in (403 `STEP_UP_REQUIRED`, asked by the service), is audited
`ai_use_case.updated` at critical severity, and every owner and administrator is told:

- turning `auto_apply` on (also after an automatic downgrade);
- raising the ceiling above `internal`;
- lowering `min_confidence` while `auto_apply` stays on.

Tightening (off, suggest, a lower ceiling, a higher confidence) needs neither and is audited at
medium severity, so turning a use case off in an incident is one click. The tenant always comes from
the token.

## Automatic downgrade

`AIUseCaseDowngradeController` (every 15 minutes, module `ai_triage`) looks at every use case in
`auto_apply` of an organization with AI on. It counts the person decisions on requests the
organization's AI filed since auto-apply was last turned on (`auto_apply_since`), newest first, at
most 50: false-positive requests whose requester is one of its AI agents or the `ai_triage` actor,
and severity requests whose requester is one of its AI agents. A rejection is an override. With at
least 10 decisions and overrides at 20 percent or more, the use case falls back to `suggest`; the
setting records when, the reason (`override_rate`) and the counts, and `ai_use_case.downgraded` is
audited (high). The write only lands over the value the sweep read, so it never overwrites an
administrator's newer change.

Only `triage` files requests today, so only it can fall back. Dismissing and undoing a suggestion
are not yet recorded and do not count.

Turning auto-apply back on is an ordinary loosening (recent sign-in, critical audit); it clears the
downgrade and restarts the window.

## Threat model

- **Prompt injection steering an automatic change.** Auto-apply never applies a severity change, a
  risk-lowering change or a flagged result; those always reach a person.
- **A compromised or careless administrator widening egress.** Loosening needs a recent sign-in, is a
  critical audit event and notifies every owner and administrator.
- **Cross-tenant reads or writes.** Every query is scoped by `tenant_id`; the tenant comes from the
  token; the sweep reads across organizations but writes one row per organization, conditionally.
- **A stale setting after a change.** Executors read the setting at every run and the AI triage
  worker reads it again before the call; an unreadable setting refuses the run.
- **Runaway auto-apply.** The downgrade falls back to suggest when people keep overriding results.

## Tests

`pkg/domain/aianalysis/use_case_settings_test.go` (defaults, validation, fail-closed normalization,
ceilings, loosening rules, downgrade threshold); `internal/app/tenantai/use_cases_test.go` (step-up,
no actor, notifications, validation, isolation, the sweep); `internal/app/aitriage/use_case_test.go`
and `fp_proposal_test.go` (off on every path, fail closed, ceiling filters the prompt, secret
snippet, auto-apply and confidence gate the false-positive request);
`internal/infra/postgres/tenant_ai_use_cases_db_test.go` (per-key writes, isolation, conditional
downgrade, sweep listing, override counts);
`internal/infra/http/routes/ai_use_case_executor_db_test.go` (off refuses before the model, suggest
changes nothing, minimum confidence, ceiling withholds fields, isolation, AI agent override counts);
`internal/infra/http/routes/ai_use_cases_route_db_test.go` (authorization matrix, step-up, audit
severities, isolation).
