# RFC-015 — Remediation groups (fix a whole "solution family" in one action)

> Status: **Phase 1–2 shipped, Phase 3 partial** (checked 2026-10-04): derivation + side-table + group list/resolve API (#288); the Remediations page with Resolve all (openctemio/ui#231); campaign resolve (#291, openctemio/ui#232) and a campaign from a group (#297, openctemio/ui#233). Not built: richer keys (Tenable solution id, OS advisory id). Group and campaign resolves are a "mark fixed" (legal steps to `fix_applied`, the claim rules, a proof-of-fix re-check per finding, a reason for every finding not updated) and never close findings: `docs/architecture/finding-status-lifecycle.md`.
> Problem: one patch fixes a whole family of CVEs, but in OpenCTEM each finding
> had to be closed one by one.

## Problem

A single fix almost always closes **many** findings:

- **OS / infra (Nessus/Tenable):** one *solution* — "Update the RHEL kernel
  package" — resolves every plugin/CVE that patch covers (Nessus reports this as the
  plugin `<solution>`).
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

### Key derivation (source-aware, on every path that creates or sees a finding)

`pkg/domain/remediation/group.go` `DeriveKey`, applied by
`internal/app/remediation/key_applier.go` from what is stored (the finding, its
package version in the software catalog and its CVE catalog entry). It runs for
findings a scan creates **and** re-sights, for CVE-matching (version-based)
findings, for findings a person creates and for license-policy findings. A
finding that no longer gets a key loses its row.

| Finding kind | Signal | `remediation_key` and title |
|---|---|---|
| Leaked secret | the keyed fingerprint of the secret value | `rotate:secret:<fingerprint>`, "Rotate the leaked <type> secret <fp8>". Only the same secret groups; a secret without a fingerprint gets no key (secret advice text is the same for every secret, so it is never a grouping signal) |
| Package (SCA, container, OS, version-based match) | ecosystem + package name + installed version + fixed versions (the scanner's list on the finding, then the CVE catalog's) | `upgrade:<ecosystem>:<name>:<target>`, "Upgrade <name> to <target>", where target is the nearest fixed version for the installed one (`RecommendedFixVersion`). Two installed versions that the same upgrade fixes share one group; a version-based match uses ecosystem `cpe` and the fix its matching range names |
| Infra / other | the specific sentences of the solution text: only sentences that name a version (`2.17.1`, `version 8`) or an advisory id (CVE, GHSA, MSnn-nnn, KB, RHSA, USN, DSA, APSB) count, at least 16 characters in all; boilerplate such as "Apply the suggested fix code." never forms a group. For code and configuration sources (`sast`, `iac`, `sarif`, `cspm`) the rule id is part of the hash, and a finding without a rule id gets no `sol` key | `sol:<source>:<sha256([rule id, ] specific sentences)>`, titled by the first specific sentence |
| pentest, or nothing specific | — | no key (ungrouped) |

Precedence: `rotate` > `upgrade` > `sol`. No key contains `/`, so a key is one
URL path segment (`/remediation-groups/{key}/resolve`); a package name with a
slash (an npm scope, a Go module path) uses `~` in the key.

**Key rules version.** Each stored key records `algorithm_version`, the
version of these rules that derived it (`KeyAlgorithmVersion`, now 3; version
1 hashed any solution text, so unrelated findings with the same boilerplate
advice shared a key). The suggestion generator never uses a key older than the
current rules: before each run it re-derives the tenant's keys when any is
stale (the backfill below, written, audited as `remediation key rules
upgrade`), and its candidate query skips stale keys, so a failed re-derivation
only delays those findings. Migration `remediation_key_algorithm_version`
marks every existing key version 1 and expires open suggestions built on
version-1 keys.

Backfill: `refingerprint -remediation-keys [-tenant <id>] [-apply]` re-derives
every finding's key, one tenant at a time, in id batches. Without `-apply` it
is a dry run on a read-only connection that prints, per tenant, the findings
scanned, keys added, changed and removed, and the key kinds before and after.
It is idempotent (a second `-apply` changes nothing).

Campaigns that track a key (`finding_filter.remediation_key`) follow the
backfill, per tenant: when every finding of the old key moves to one new key,
and no other finding gets that key, the campaign is retargeted to it
(`would_retarget` in a dry run), its `version` is bumped and an audit entry
(`remediation_campaign.updated`, actor `refingerprint -remediation-keys`,
old and new key) is written; when they split over several keys, lose their
key, or share the new key with other findings (old keys merging, which would
widen the campaign), the campaign is reported as `ambiguous` and left alone; a campaign tracking a key no finding has is
reported as `stale`. The dry run prints these as warnings with the finding
counts. A retarget only applies while the campaign still tracks the old key.

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
  asset_count, severity_rollup, fix_available}`.
- `POST /api/v1/findings/remediation-groups/{key}/resolve` — marks all open
  findings in the group fixed. Body: `{status: "fix_applied", resolution}`
  (the note is required; `resolved` is refused: each finding is verified on
  its own).
  Internally: resolve the group's open finding IDs → `BulkGuard.CheckBulk` →
  `BulkUpdateFindingsStatus`. Tenant from the authenticated context; pentest
  findings excluded (they own their lifecycle).

Default recommended status = **`fix_applied`** (patched, pending verification),
so the next full rescan confirms via the existing auto-resolve and flips to
`resolved` — accurate to reality (a patch may not have landed everywhere).
There is no immediate close for a group.

## Phases

| Phase | Work |
|---|---|
| **1** (#288) | `remediation_key` column + derivation at ingest + group query/repo + `GET /remediation-groups` + `POST /remediation-groups/{key}/resolve` (reuses BulkGuard+BulkUpdate) + backfill. Tests incl. DB round-trip. |
| **2** | UI "Remediations / By solution" view with per-group **Resolve all**; wire the `fix_applied → verified-on-rescan` loop end to end. |
| **3** (partial) | Unify with Remediation Campaigns — **campaign can now actively resolve its open findings** (`POST /remediation/campaigns/{id}/resolve`, reuses the finding bulk path + abuse guard; was a passive tracker). Remaining: group→campaign/ticket spawn; richer keys (Tenable solution-id, OS advisory id). |

## Testing

- Key derivation: SCA (component) vs Nessus (solution) vs none → correct/NULL.
- Group query rolls up counts/severity; excludes closed + pentest.
- Group resolve → all open members transition; BulkGuard ceiling enforced;
  tenant isolation (a key in tenant A never touches tenant B).
- DB round-trip of `remediation_key` against the real findings schema.

CI green (`gh pr checks`) before done. No Generated-By/Co-Authored-By footers.
