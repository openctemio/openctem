# RFC-057: Finding evidence and honest retests

| | |
|---|---|
| Status | Accepted (owner delegated 2026-10-07: "do the best"; mask by default with an audited reveal; a tool-agnostic evidence contract) |
| Scope | api (`pkg/domain/evidence`, `internal/app/evidence`, ingest, retest), web (finding Evidence tab, Retest section); contract: CTIS 1.6 `evidence_items[]` (ctis), the emitter and retest verdict evidence (sdk-go), nuclei raw evidence and `-ms` attempts (sensor) |
| Architecture | [finding-evidence.md](../architecture/finding-evidence.md), [continuous-retest.md](../architecture/continuous-retest.md) |
| Related | RFC-039 (continuous retest), RFC-040 (mutual distrust), RFC-050 (asset access model), RFC-055 (tool contract) |

## 1. Problem

1. **A retest said "Fixed" when it proved nothing.** The retest passed the
   finding's matched-at URL to the template as its input. A template appends
   its own path to the input, so the re-run requested the path twice, got a
   404, did not match, and the finding was resolved. "Reachable" was a TCP
   connect to the host, which a live host always passes. A single non-match
   moved the finding to `resolved`.
2. **A finding did not show what the tool did.** The nuclei sensor sends the
   request, response, curl command and extracted values; the platform kept
   none of them. There was no way to see which request was sent and what came
   back.

## 2. Decisions

### E1 Evidence is typed, tool-agnostic and part of the contract

An evidence item (`http_exchange`, `raw_text`, `command_output`,
`file_excerpt`, `screenshot`, `curl`, or any other kind, kept as text) with
match locations, extracted values, a content hash and optional
tool-marked sensitive spans. CTIS 1.6 carries it as `finding.evidence_items[]`
and in retest verdicts; the SDK emits it with caps and marked spans; the
platform accepts every kind from every tool and enforces its own caps.

### E2 Masked by default, reveal on demand

The platform always runs its own detector (headers, cookies, URL and body
secrets, credential shapes, tool-marked spans). Values are replaced everywhere
in the item by `«secret:kind#n»` and stored AES-256-GCM encrypted apart, bound
to tenant, item and placeholder, for the tenant's secret retention (default
30 days, the masked evidence 365). Reveal needs `findings:evidence:reveal`
(owner/admin by default, assignable), data scope, step-up (API keys cannot)
and a per-user rate limit; it returns only the requested values with
`no-store`, is audited before it returns, and appears on the finding's
timeline. The UI re-masks after 60 seconds; "Copy curl" is masked, "Copy curl
with secrets" is a reveal.

### E3 Evidence never travels

It lives in its own tables. Finding lists and detail, exports, notifications,
tickets, webhooks and AI-triage prompts never read it. Hostile content is
rendered as text only.

### R1 The retest input is the origin

The re-run's input is `scheme://host[:port]` of the matched-at URL (a host
that is not the asset's falls back to the asset). Migration 001175 voids the
"fixed" outcomes of retests that ran with a path input.

### R2 A non-match is not proof of a fix

Retest outcomes become `confirmed_fixed` (the attempt requested the original
endpoint, an HTTP answer came back that is not a block, an auth failure or a
server error, the check evaluated it and did not match, and the template is
the one last seen), `not_reproduced` (no match, but the endpoint was not
proven to be checked: no attempt evidence), `still_vulnerable`, and
`inconclusive` with a reason code (`unreachable`, `blocked`, `auth_changed`,
`server_error`, `endpoint_mismatch`, `template_changed`, `template_missing`,
`no_result`, `error`). Only `confirmed_fixed` moves an open finding, to
`validated_fixed` ("Verified fixed — awaiting confirmation"); it resolves only
when the tenant enabled `settings.retest.auto_resolve`. A tool verdict
`fixed` without attempt evidence is `not_reproduced`.

### R3 The label says what happened

"Verified fixed — https://h/x answered 404; template T (sha256:…) did not
match", "Not reproduced — …", "Inconclusive: blocked — https://h/x answered
403", each linked to the attempt's evidence.

## 3. Threat model

See [finding-evidence.md §Threat model](../architecture/finding-evidence.md#threat-model).
In short: secrets of scanned targets never leave the encrypted store except
through an authorized, stepped-up, rate-limited, audited reveal; tenant and
data scope are enforced on every route (404); hostile tool content is text;
storage is bounded; a sensor cannot close a finding with a bare verdict.

## 4. Implementation

| Part | Where |
|---|---|
| R1 origin target, void false fixes (migration 001175) | openctem#1307 |
| E1–E3 evidence store, masking, reveal, ingest of nuclei properties, viewer (migration 001196) | this PR series |
| R2–R3 outcomes, policy, attempt evidence, labels | follow-up openctem PR |
| CTIS 1.6 `evidence_items`, SDK emitter and verdict evidence, nuclei raw evidence and `-ms` attempts | ctis, sdk-go, sensor (tool contract track, RFC-055) |
