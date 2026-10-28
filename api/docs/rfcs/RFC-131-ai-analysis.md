# RFC-131: AI analysis (governed suggestions, the analyze contract, the AI analyst)

| | |
|---|---|
| Status | Accepted (2026-10-28). In review: governance core (AI suggestions with provenance, per-use-case mode, apply rules, undo, automatic downgrade), reversible masking of AI context, the `openctem.analyze/v1` contract. Designed: the built-in executor writing runs through the contract, the AI analyst worker, third-party analysts |
| Scope | api (governance, masking, contract, built-in executor), web (Settings > AI use cases and masking, shared AI badge, suggestion card), sdk-go (analyst harness, conformance cases), sensor (analyst image), docs |
| Architecture | [ai-analyze-contract.md](../architecture/ai-analyze-contract.md), [ai-triage.md](../architecture/ai-triage.md), `ai-analysis.md` (governance) |
| Related | RFC-040 (mutual distrust, signed jobs), RFC-016 and RFC-062 (MCP, AI egress policy), RFC-094 (the platform depends on contracts only), RFC-030 (scan distribution) |

## 1. Summary

AI helps analysts triage findings, plan remediation and summarise, and later
acts with tools through an AI analyst that pairs with the platform like a
sensor. Three rules hold for every AI path:

1. **Every AI result is a suggestion with provenance.** It records the run that
   produced it: executor, provider and model, prompt template id and digest,
   output schema, bundle digest, the fields sent and withheld, tokens and cost.
2. **The platform decides what a suggestion does to risk** (adds information,
   raises risk, lowers risk) from the finding's facts. The organization picks
   per use case `off`, `suggest` or `auto_apply`. Auto-apply applies additive
   suggestions only. Anything that lowers risk is an approval request under the
   organization's four-eyes rules, in every mode. Severity and priority changes
   always wait for a person.
3. **The platform decides what the model may see.** A context bundle holds only
   the fields the use case's data class ceiling allows, with sensitive values
   replaced by typed placeholders the platform alone can map back; secrets are
   never reversible.

## 2. The `openctem.analyze/v1` contract

One contract for every executor, published as versioned JSON Schemas in
`api/pkg/sensorproto/analyze/schemas/` (the sensor protocol lives in the API,
RFC-094):

| Schema | `$id` | What |
|---|---|---|
| job | `https://openctem.io/schemas/analyze/job/v1.json` | kind (`triage.v1`), use case, subject, bundle (digest, data class, fields sent and withheld, masked), output schema, prompt template id and digest, model policy, investigation grant (multi-step kinds), budgets, deadline |
| result | `https://openctem.io/schemas/analyze/result/v1.json` | status, fixed error code, suggestions, usage, template, run record digest |
| suggestion | `https://openctem.io/schemas/analyze/suggestion/v1.json` | one typed suggestion: `verdict`, `severity`, `remediation_steps` or `summary`, each with a closed payload, confidence 0..1 and evidence references (`bundle:<field>` or `tool:<n>`) |
| output per kind | `.../output/triage/v1.json`, `.../output/remediation/v1.json`, `.../output/summary/v1.json` | what a single-shot model call must return for the kind |

Kinds are versioned; a new kind or version never changes an existing one.
Single-shot kinds (`triage.v1`, `remediation.v1`, `summary.v1`) may run in the
API process (the built-in executor). Multi-step kinds only ever run on an analyst
worker: hostile finding text must never drive a loop inside the process that
holds every organization's data.

Structural controls on every output: closed schemas (a model cannot add a
direction, a state, a target or any other field), enums and bounds, one
suggestion per kind, evidence in a fixed shape that must resolve to something the
run really had, free text displayed as plain text only. Validation errors name
the failing location and keyword, never the content.

## 3. Governance

Specified in the architecture doc `ai-analysis.md`: the tables
(`ai_runs`, `ai_suggestions`, `tenant_ai_use_cases`), the apply rules, undo, the
override rate (20 % of the last 50 decisions downgrades auto-apply to suggest
until an administrator re-enables it), the routes and their gates.

## 4. Masking

Every bundle is pseudonymised per run: typed placeholders derived with a per-run
HMAC key (same value, same placeholder within the run; unlinkable across runs and
organizations), structure kept where it helps (subdomain labels, IP class, CIDR
membership as trusted facts), secrets replaced by `SECRET_n` with type and length
only and never mapped back, token-shaped input escaped before masking. The
mapping stays on the platform, encrypted, with a TTL. Output is de-tokenised by
the platform; unknown placeholders force review. A worker's tools receive real
targets only for the bindings the signed grant carries for the subject.

## 5. The AI analyst (designed)

A sensor role `analyst` on the existing worker type with a grant profile
`ai-analyst` (command type `analyze` only, never `scan` or `collect`; a sensor is
an analyst or a scanner, never both). Jobs are signed (RFC-040); the bundle is
sealed to the claiming worker's key at claim time; the harness checks policy
before every tool call; tools run in the per-task sandbox and egress forwarder
with the subject asset as the only target; budgets bound steps, tokens, time and
cost. Data classes route jobs: `tenant_only` data goes only to a worker the
organization runs. Third-party analysts use the same contract and a conformance
suite.

## 6. Decisions

| # | Decision |
|---|---|
| D1 | The AI analyst is a sensor role, paired and governed like any sensor |
| D2 | A sensor is an analyst or a scanner, never both |
| D4 | Own small harness with a policy check before every tool call |
| D5 | `restricted` data reaches a platform worker only with the organization's opt-in per use case, a recent sign-in and an audit row |
| D6 | `tenant_only` data reaches only a worker the organization runs |
| D7 | The analyst runs passive and safe tools on the subject asset only; anything else is a follow-up request through the scope gate |
| D8 | Auto-apply covers additive changes; risk-lowering changes always go through approval |
| D11 | The built-in executor keeps single-shot kinds in the API process |
| D13 | Third-party analysts through this contract and a conformance suite |
| D15 | `ai_triage_results` is copied into `ai_runs` and `ai_suggestions`, then dropped in a contract step |
| D16 | Automatic downgrade at 20 % overrides over the last 50 decisions, on by default |
| D17 | No AI result changes priority by itself; any AI effect on priority is a suggestion |

## 7. Threat model

| Asset | Threat | Control |
|---|---|---|
| Finding state | injected text steers the model to hide risk | risk-lowering changes are approval requests in every mode; severity changes wait for a person |
| Finding state | the model claims a direction, state or extra field | closed schemas; the platform computes the direction from server facts |
| Analyst attention | fabricated evidence | references must resolve; otherwise `needs_review`, never auto-applied |
| Tenant data | over-collection | fields by data class ceiling, withheld fields recorded, masking with platform-held mapping |
| Tenant data | cross-tenant read or action | tenant in every query and key, by-id routes answer 404, data scope and pentest membership on the subject |
| Configuration | auto-apply or a higher data class turned on by mistake or with a stolen session | owner or admin, recent sign-in, critical audit row |

## 8. Implementation

| Piece | State |
|---|---|
| Retire the inert `ai_triage.*` sub-modules; regression test that AI never changes severity or priority by itself | in review |
| Governance core (tables, apply engine, undo, downgrade, routes) | in review |
| Reversible masking (`pkg/aimask`, mapping store, masking policy and preview) | in review |
| `openctem.analyze/v1` schemas and validator (`pkg/sensorproto/analyze`) | in review |
| Built-in executor for `triage.v1`, `remediation.v1`, `summary.v1` through the contract, with bundle builder, masking and provenance | designed |
| Web: Settings > AI use cases and masking, shared AI badge, suggestion card and "why" drawer | in review |
| AI analyst worker, harness, conformance cases | designed |
