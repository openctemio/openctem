# RFC-013 — DefectDojo co-existence connector

> Status: **Implemented** (Phases 1–2): converter (`internal/infra/importer/defectdojo/converter.go`), REST client, scheduled per-tenant sync worker, manual `POST /api/v1/integrations/defectdojo/sync`, and the DefectDojo-dependency ratio (`finding_analytics_repository.go`). Phase 3 (switching the connector off) is an operator choice, not code work.

## Problem & approach

DefectDojo parses **200+** scanner output formats; OpenCTEM has ~7 native
parsers. Rather than block on writing hundreds of parsers, organizations that
already run DefectDojo can use it as an ingestion front-end:

- **DefectDojo = an ingestion front-end** (its parser breadth).
- **OpenCTEM = the system of record** (everything users act on: prioritization,
  validation, mobilization).

The connector is designed so DefectDojo can be phased out over time, which is
only achievable if it is designed against lock-in from day one.

## The one non-negotiable principle

> **OpenCTEM is the system of record from day 1. DefectDojo is a replaceable
> input adapter, run headless.**

If DefectDojo becomes a source of truth, or users work inside it, it can never be
removed. Four guardrails enforce removability:

1. **No reverse dependency.** No OpenCTEM core feature may call DefectDojo's API.
   DefectDojo sits **behind the connector**; removing it = removing one adapter.
2. **CTIS is the only internal contract.** The DefectDojo connector emits **CTIS**;
   future native parsers emit **CTIS**. Downstream (dedup, prioritize, validate)
   never knows the source → sources are swappable transparently.
3. **DefectDojo runs headless.** Users see only OpenCTEM. No DefectDojo UI habit
   to unwind later.
4. **Measure the dependency.** Track the **DD-dependency ratio** = share of
   finding volume that arrives *only* via DefectDojo (tools we cannot yet parse
   natively). This is the metric that tells us when DefectDojo can be dropped.

## Phased plan with explicit exit criteria

| Phase | Work | Transition gate |
|-------|------|-----------------|
| **1 — Co-exist** | DD→CTIS connector (one-way), DD headless | depending on DD for most parsers |
| **2 — Shrink** | native parsers for the tools *actually in use* (freq-ranked, not all 200); optionally push prioritization/validation results *back* to DD | native covers ≥ ~80% of finding volume |
| **3 — Cut** | flip a flag to disable the connector; DD becomes optional / removed | DD-dependency ratio < ~10–15% |

The goal is **not** to reimplement every DefectDojo parser. It is covering the 10–20 tools
that make up ~90% of a given customer's volume, after which the DefectDojo connector has no
reason to remain.

## Design

### Data flow (Phase 1 — one-way)

```
DefectDojo REST API  ──(pull, per-tenant)──►  connector  ──CTIS──►  OpenCTEM ingest
   /api/v2/findings/                          (converter)          (async, RFC-005)
```

- **Per-tenant + tenant-isolated** (platform rule): DefectDojo creds are a
  `defectdojo` **integration** (AES-encrypted, `ListByProvider(tenantID)`); the
  ingest tenant is the authenticated tenant, never anything in the DD payload.
- **Converter** (`internal/infra/importer/defectdojo/`) mirrors
  `internal/infra/scanner/nessus/converter.go`: DefectDojo finding JSON → a CTIS
  `Report`. Pure and unit-testable without a live DefectDojo.

### Dedup / idempotency (the double-dedup trap)

Both systems dedup. To avoid OpenCTEM re-deduping DefectDojo findings into a
mismatch, each converted finding carries DefectDojo's stable identity:

- `PartialFingerprints["defectdojo/finding_id"]` and `["defectdojo/hash_code"]`
- a deterministic `Fingerprint = "defectdojo:<hash_code|id>"`

so re-imports map to the same OpenCTEM finding (idempotent), and the DefectDojo
finding remains traceable.

### Coverage / auto-resolve safety

The report is marked **`coverage_type: partial`**. A DefectDojo import is *not* a
full scan of any scope, so it **must not** trigger OpenCTEM's asset-scoped
auto-resolve (which would wrongly resolve findings from other sources). This is a
correctness invariant, not an optimization.

### Status is one-way (Phase 1)

DefectDojo → OpenCTEM only. Once a finding is in OpenCTEM, all state changes
(triage, risk-accept, resolve, validate) happen **in OpenCTEM** (the system of
record). Pushing state *back* to DefectDojo is deferred to Phase 2 with an
echo-guard (mirrors the ticketing bidirectional-sync design).

## Changes

- **Phase 1 (this PR):**
  - `pkg/domain/integration`: add `ProviderDefectDojo` (security category).
  - `internal/infra/importer/defectdojo/converter.go`: `Convert(findings, opts)
    → *ctis.Report`, with the dedup/coverage rules above. Unit-tested with a
    representative DefectDojo `/api/v2/findings/` payload.
- **Phase 2 (next PR):** the DefectDojo REST **client** (paginated pull, per-tenant
  creds resolver mirroring the Jira/SMTP resolver) + a scheduler/worker that pulls
  on an interval and POSTs to ingest, + the DD-dependency metric.
- **Phase 3:** feature-flag the connector off; native-parser coverage dashboard.

## Testing

- Phase 1: converter maps severity/CVE/CWE/CVSS, endpoints→network asset,
  file_path→code location; carries `defectdojo/finding_id` + `hash_code`;
  emits `coverage_type: partial`; a re-convert is byte-stable (idempotent
  fingerprint).
- Phase 2: live pull against a DefectDojo instance behind the `_e2e_common.sh`
  harness; assert findings land + carry the external ref + do not auto-resolve
  native findings.

Each phase is a separate PR → `develop`, referencing this RFC.
