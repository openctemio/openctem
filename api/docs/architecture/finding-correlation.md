# Cross-rule finding correlation

Two scanner rules can report one issue: a generic detection and a CVE
template on the same injection point (for example a generic open redirect at
`/oast.me` and the CVE-2025-54793 template at `/interact.sh/en`, where both
path segments are the templates' out-of-band redirect targets). Correlation
folds such detections into one finding. **It may reduce noise, never
coverage**: only the tiers proven safe change a status, every change is
reversible, and anything less certain is a suggestion a person confirms.

Code: `pkg/domain/correlation` (decisions, pure), `internal/app/ingest/correlation_findings.go`
(at ingest), `internal/infra/postgres/finding_correlation_repository.go`
(storage), `internal/infra/http/handler/finding_correlation_handler.go` (API).
Data, not code: `pkg/domain/correlation/dast.json` (out-of-band payload
domains, injection CWEs, broad CWEs). DAST is the first kind; SAST (two rules
on one line and CWE) and SCA (one CVE and package from two scanners) reuse
the framework later.

## Injection point

Each DAST finding stores its injection point (`finding_injection_points`):
scheme, host and port; the path; the method; the parameter names with their
location (`query:q`, `form:user`). Nothing is generalized: `/user/123` and
`/user/456` differ, `www` and the apex differ, `http` and `https` differ.
A payload is removed from the path only when **both** hold: the path ends
with exactly the value the detection's own evidence shows (a response
`Location` header), and its host is a listed out-of-band domain. A segment
that merely looks like a payload host is kept.

## Tiers

| Tier | When | Effect |
|---|---|---|
| auto | same asset, same CWE set (every CWE an injection CWE), same injection point, and either one CVE among them (generic + specific, or the same CVE) | the member becomes a duplicate of the primary (`status = duplicate`, `duplicate_of`, `resolution = correlated`); the primary is the earliest finding with the CVE |
| suggested | same asset, origin and payload-free path, not auto | a "possibly related" row; nothing changes until a person confirms it |
| never | another asset, different CWEs, two different CVEs, a broad or missing CWE (auto) | — |

## Lifecycle

- Only open findings (new, confirmed, in progress, fix applied) are
  correlated. Triage never propagates: when the primary leaves the open
  statuses its members are released and stand alone.
- Re-derived on every scan of the asset. A member the scan saw while its
  primary was not seen is released (the CVE may be patched while the generic
  detection still fires). A released member takes the new-finding path
  (notifications, tickets).
- The primary's severity is the group's worst while the group exists and is
  restored on release; the gate and metrics count duplicates as accepted or
  not at all, so the group counts once at its worst severity.
- A person un-duplicates in one action (`POST /api/v1/findings/{id}/correlation/release`,
  findings:triage): the member's status from before is restored and the pair
  is never linked automatically again. `POST /api/v1/findings/{id}/correlation/confirm`
  (findings:triage) confirms a suggestion. Every link and release is audited.
- `GET /api/v1/findings/{id}/detections` (findings:read) returns
  `detections: [{finding_id, rule_id, title, matched_url, first_seen, primary}]`
  and `possibly_related` (same shape). The finding is checked against the
  caller's tenant and data scope; correlations never cross assets.
- Kill switch per organization: `PATCH /api/v1/tenants/{tenant}/settings/finding-correlation`
  `{auto_disabled, suggestions_disabled}` (admin, settings:write); both tiers on by default.
- Existing findings: `refingerprint -correlate` (dry run: "link N, suggest N")
  then `-apply`; idempotent.

## Tests

`tests/integration/testdata/correlation/dast.json` is the golden corpus: the
open-redirect pair must merge, and one negative pair per guardrail (parameter
names, method/location, broad CWE, missing CWE, two CVEs, scheme, www/apex,
a lookalike segment, ids) must not. Any wrong merge fails CI.
