# RFC-015 — Remediation groups (fix a whole "solution family" in one action)

> Status: **Phase 1 shipped** (derivation + side-table + group list/resolve API)
> Problem owner request: "Tenable groups CVEs into a solution family; one patch
> fixes the whole family. In OpenCTEM you have to close each finding one by one."

## Problem

A single fix almost always closes **many** findings:

- **OS / infra (Nessus/Tenable):** one *solution* — "Update the RHEL kernel
  package" — resolves every plugin/CVE that patch covers. Tenable exposes this as
  its **Remediations / Solutions** view.
- **SCA / containers:** upgrading one dependency (`lodash → 4.17.21`) resolves
  every finding on that package below the fixed version.

Today OpenCTEM captures the fix text **per finding** (`findings.remediation`
JSONB, set from Nessus `<solution>` / SCA fixed-version) but has **no grouping
key**, so an operator who applied one patch must hand-select or `done` each
finding. Bulk-close exists (`BulkUpdateFindingsStatus` + `BulkGuard`) but only
by an explicit finding-ID list — there is no "resolve everything this patch
fixes" action.

## What already exists (reuse, don't rebuild)

- `VulnerabilityService.BulkUpdateFindingsStatus(FindingIDs, status, resolution)`
  — batched 2-query status change, Jira-sync aware.
- `finding.BulkGuard` — size ceiling + hourly budget + operator-approval gate.
- Status model already has the two states we need:
  `fix_applied` ("marked fixed, **pending verification**") and `resolved`
  ("verified fixed by scan or review"). **No new status needed.**
- `ingest.AutoResolveStaleByAssets` — a full rescan already auto-resolves
  findings that disappear (the verification path).
- Finding already carries `ComponentID` + `FixedVersions` (SCA) and
  `Remediation.Recommendation` (Nessus solution) — the raw material for a key.

## Design

Add a derived **`remediation_key`** to each finding: a stable fingerprint of the
*fix action* that resolves it. Findings sharing a key form a **remediation
group**. Expose a group view and a group-level resolve that reuses the bulk
machinery.

### Key derivation (source-aware, at ingest)

Computed in `processor_findings.go` right where remediation/component are set:

| Finding kind | Signal | `remediation_key` |
|---|---|---|
| SCA / container / OS package | component identity (purl/name+ecosystem) + a fix is available | `sca:<component-identity>` — all findings on that component group; the upgrade fixes them together |
| Nessus / Tenable / infra | `Remediation.Recommendation` (the solution text) | `sol:<sha256(normalized(solution))>` |
| otherwise | — | `NULL` (ungrouped) |

Normalization: trim, lowercase, collapse whitespace, drop volatile tokens. NULL
key = not groupable (never grouped, never bulk-touched by this feature).

**Scope of a group:** the key is fix-identity only; the group query is always
tenant-scoped and may be further filtered by asset/branch so "resolve group"
never crosses tenant boundaries.

### Schema (migration 000186) — feature-owned side-table

Implemented as a **side-table**, NOT a column on `findings`. The findings table is
the most central/complex in the system; adding a column means editing its huge
INSERT/UPDATE/SELECT/scan (one mis-aligned scan breaks every finding read). A
side-table keeps the grouping concern out of core, is far lower blast-radius, and
lets the feature be dropped without touching findings (aligns with the
module-decoupling goal).

```sql
CREATE TABLE finding_remediation_keys (
    finding_id      UUID PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    remediation_key TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_finding_remediation_keys_tenant_key
    ON finding_remediation_keys (tenant_id, remediation_key);
```

One row per finding, CASCADE-deleted with the finding, re-derived idempotently at
each ingest (`FindingProcessor` post-insert applier). Group queries JOIN back to
findings read-only for status/severity/asset rollups. Additive — zero behavior
change until populated.

### API

- `GET /api/v1/findings/remediation-groups` — `GROUP BY remediation_key` over
  **open** findings; returns `{key, title (the fix action), finding_count,
  asset_count, severity_rollup, fix_available}`. The Tenable "Remediations" tab.
- `POST /api/v1/findings/remediation-groups/{key}/resolve` — resolves all open
  findings in the group. Body: `{status: "fix_applied"|"resolved", note}`.
  Internally: resolve the group's open finding IDs → `BulkGuard.CheckBulk` →
  `BulkUpdateFindingsStatus`. Tenant from the authenticated context; pentest
  findings excluded (they own their lifecycle).

Default recommended status = **`fix_applied`** (patched, pending verification),
so the next full rescan confirms via the existing auto-resolve and flips to
`resolved` — accurate to reality (a patch may not have landed everywhere). An
operator can choose `resolved` for immediate close.

## Phases

| Phase | Work |
|---|---|
| **1** (this PR) | `remediation_key` column + derivation at ingest + group query/repo + `GET /remediation-groups` + `POST /remediation-groups/{key}/resolve` (reuses BulkGuard+BulkUpdate) + backfill. Tests incl. DB round-trip. |
| **2** | UI "Remediations / By solution" view with per-group **Resolve all**; wire the `fix_applied → verified-on-rescan` loop end to end. |
| **3** (partial) | Unify with Remediation Campaigns — **campaign can now actively resolve its open findings** (`POST /remediation/campaigns/{id}/resolve`, reuses the finding bulk path + abuse guard; was a passive tracker). Remaining: group→campaign/ticket spawn; richer keys (Tenable solution-id, OS advisory id). |

## Testing

- Key derivation: SCA (component) vs Nessus (solution) vs none → correct/NULL.
- Group query rolls up counts/severity; excludes closed + pentest.
- Group resolve → all open members transition; BulkGuard ceiling enforced;
  tenant isolation (a key in tenant A never touches tenant B).
- DB round-trip of `remediation_key` against the real findings schema.

CI green (`gh pr checks`) before done. No Generated-By/Co-Authored-By footers.
