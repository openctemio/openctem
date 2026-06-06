# RFC-008: Native Shift-Left CI/CD Code Scanning (agent-first)

- **Status**: Phases 1–5 + 7 shipped; Phase 6 (export) partial
- **Created**: 2026-06-06
- **Owner**: Platform / Agent
- **Problem**: We want first-class, **self-contained** shift-left code security in CI/CD — SAST/SCA/secret scanning that runs in the pipeline, decorates PRs/MRs, and gates merges — using **our own agent + platform**, not a third-party tool and not a back-forward bridge. The bar: best-in-class, on top of OpenCTEM's multi-tenant + risk-prioritization advantages.

> **Decision context.** We studied califio **code-secure** (an ASPM/DevSecOps tool: .NET API + Angular UI, single-org, thin Go scanner wrappers → `/api/ci/*` + CI-TOKEN, PR/MR inline comments, severity gate). We will **not** depend on it or bridge to it. We adopt the *good ideas* into our own agent.

---

## 0. Grounding — we are already a peer (and ahead in places)

An audit of our agent (2026-06) corrected an earlier mis-assessment. Our agent + `sdk-go` **already implement the shift-left pipeline**:

| Capability | Where | Status |
|---|---|---|
| CI env auto-detect (GitHub/GitLab/Bitbucket/Azure) + repo/commit/branch/MR + `TargetBranchSha` baseline | `sdk-go/pkg/gitenv` | ✅ |
| Scan lifecycle handler (`OnStart`→baseline, `HandleFindings`, `OnCompleted`) | `sdk-go/pkg/handler` | ✅ |
| PR/MR inline comments on changed files | `handler.RemoteHandler` + `gitenv.CreateMRComment`, `-comments` | ✅ |
| Changed-file scoping (`ChangedFileOnly`) | agent `main.go` → `HandleFindings.ChangedFiles` | ✅ |
| Branch-aware CTIS (`buildBranchInfo` → PR number/URL) | agent `main.go` | ✅ |
| Per-(finding,branch) occurrence model + first/last-seen + denormalized repo | `finding_branch_occurrences` (mig 000173) | ✅ written + read (branch filters) |
| **PR new-vs-base diff** (gate + comments scoped to findings the PR introduces) | `baseline-diff` endpoint + `Client.BaselineDiff` + `gate.FilterNewFindings` | ✅ **Phase 3 (api #160, sdk-go v0.4.0, agent #28)** |
| **Idempotent PR comments + sticky summary** | `sdk-go/pkg/{gitenv,handler}` | ✅ **Phase 4 (sdk-go #33/#34)** |
| CI gate + per-finding suppressions | `agent/internal/gate` | ✅ |
| **Risk-aware gate** (block CISA-KEV / exploit-available below threshold) | `agent/internal/gate` | ✅ **Phase 1, agent #27** |
| Scanners: semgrep, gitleaks, trivy, codeql, nuclei, recon | `sdk-go/pkg/scanners` | ✅ (more than code-secure) |
| Multi-tenant, prioritization (EPSS/KEV/VPR), transactional outbox, tenant-scoped tokens | api | ✅ (code-secure has none of these) |

**Conclusion:** the work is *audit → polish to best-in-class*, not rebuild. The gaps are behavioral maturity, not missing architecture.

## 1. What code-secure does better today (the learnables)

1. **MR new-vs-target suppression** — on a PR scan they pull the **target branch's** findings and treat them as "known", so the PR only flags findings genuinely **new vs target** (not pre-existing tech debt). Big PR-noise reduction. *✅ Now shipped — see Phase 3.*
2. **Per-branch occurrence lifecycle on non-default branches** — they mark per-scan status `Fixed` even on feature branches (without touching the canonical status). Our auto-resolve runs **only** on the default branch, so a feature-branch occurrence never transitions to `auto_fixed`.
3. **Reading the per-branch data** — they use per-scan status everywhere (views, gate, comments). Our occurrences are *written but not read yet* (mig 000173 is additive).
4. **Comment idempotency is absent in both** — re-running a PR re-posts duplicate comments. *✅ Now shipped (Phase 4) — and we went beyond with a sticky PR summary.*
5. **Reporting export** (PDF/Excel) + weekly digest + role-based routing (validator/developer) — platform-side; we have report *schedules* but not export depth.

## 2. What we will NOT copy (we already beat it)

- Single-org model → we are strictly **multi-tenant** (`WHERE tenant_id`).
- Global, never-expiring CI tokens → we use **tenant-scoped** keys.
- Severity-only gate → we gate by **real risk** (EPSS/KEV/VPR) — already shipped.
- Fire-and-forget alerts → we use the **transactional outbox** (+ dead-letter alert).
- Rule-only mute → we keep **per-finding suppression**.
- Per-repo finding `Identity` → we keep **branch-independent fingerprint identity** (cross-branch + cross-repo correlation).

## 3. Plan — phases

Each phase: own PR(s), tests, CI-green, tenant-isolated, mock-first where no infra. Reuse existing pipeline (gitenv/handler/gate/ingest/occurrences/outbox/SCM clients).

### Phase 1 — Risk-aware gate ✅ SHIPPED (agent #27)
Block CISA-KEV / exploit-available findings even below the severity threshold; suppressed never blocks; backward compatible; tested.

### Phase 2 — Per-branch occurrence lifecycle ✅ SHIPPED (pre-existing in ingest)
Already implemented before this RFC: ingest `service.go` Step 3b `AutoResolveStaleBranchOccurrences` runs for any full-coverage scan and transitions a branch's occurrences to `auto_fixed` without touching the canonical `findings.status` (default-branch-only invariant preserved).
Make the occurrence write-side *correct* so reads are trustworthy:
- On a **full-coverage scan of a non-default branch**, transition that branch's occurrences to `auto_fixed` when a finding is no longer seen — **without** touching the canonical `findings.status` (which stays default-branch-only). Preserves the existing safety invariant.
- Keep `first_seen`/`last_seen` (+ scan + commit) accurate per branch.
- Tests: feature-branch fix marks occurrence `auto_fixed`; canonical untouched; default-branch behavior unchanged.

### Phase 3 — MR new-vs-target suppression ✅ SHIPPED (api #160, sdk-go #35 / v0.4.0, agent #28)
Server computes, for a PR/MR scan, which findings are **new vs the base branch**, and the agent scopes its gate + comments to that set.
- **api** `POST /api/v1/agent/ingest/baseline-diff` `{repository, base_branch, fingerprints}` → `{new_fingerprints, pre_existing_fingerprints, base_branch_scanned}` (auth: agent context; tenant from `agt.TenantID`). Backed by `FindingRepository.FingerprintsOpenOnBranch` over `finding_branch_occurrences` (tenant + branch + `status='open'`); unknown repo/branch ⇒ all new. Pure `partitionByBaseline` unit-tested.
- **sdk-go** `Client.BaselineDiff(repo, baseBranch, fps) → newFPs`; `handler.HandleFindingsParams.NewFingerprints` scopes inline comments to new findings; sticky summary reports "N new in this PR (of M)".
- **agent** `gate.FilterNewFindings` reduces reports to the PR's new findings before the gate (risk-override + severity still apply to that set); `main.go` calls `BaselineDiff` per report in a PR context (`apiClient && push && MR`). **Fails safe**: a diff error treats findings as new (never hides them). Non-PR scans unchanged.
- Naming: endpoint named `baseline-diff` (consistent with sibling `/ingest/check`); fields `new_fingerprints` / `pre_existing_fingerprints` / `base_branch_scanned`.
- Tests: pre-existing-on-base not flagged; only-on-source flagged new; no-fingerprint treated as new for visibility; sources not mutated.

### Phase 4 — PR comment idempotency + provider parity ✅ SHIPPED (sdk-go #33, #34)
- Idempotency via a hidden marker (`<!-- openctem-finding:<key> -->`, key = fingerprint else `rule:path:line`): `gitenv.ExistingFindingMarkers()` lists prior comments, the handler skips already-commented findings on re-run. GitHub (PR review comments) + GitLab (MR discussions) confirmed.
- **Beyond code-secure:** a single sticky PR/MR summary comment (`gitenv.UpsertSummaryComment` + `SummaryMarker`) updated in place each run — severity table, or a clean state.

### Phase 5 — Per-branch read surface ✅ SHIPPED (pre-existing)
- Findings API already supports `branch_id` / `branch_status` filters + `occurrence_count`, reading the mig 000173 occurrence data.

### Phase 6 — Reporting / compliance 🟡 PARTIAL
- HTML executive summary exists; PDF/Excel export + weekly digest + role-based routing still to build, on the existing notification/outbox infra. Fills the compliance-reporting gap (also helps the .sc-replacement story in RFC-007). **Only remaining phase.**

### Phase 7 — DX & docs ✅ SHIPPED (pre-existing)
- `agent/ci/{github,gitlab}/` ship ready-to-paste Action / CI recipes; `-check-tools`/`-install-tools` UX exists.

## 4. Risks & mitigations
- **Canonical status corruption from non-default branches** → Phase 2 strictly writes occurrence status only; canonical stays default-branch + full-coverage gated (existing invariant, reaffirmed by tests).
- **PR comment spam / duplicates** → Phase 4 idempotency.
- **SCM API rate-limit / auth** → reuse per-tenant client-resolver (RFC-006 pattern); back off.
- **Scope creep** → phases independent and individually mergeable.

## 5. Non-goals
- Re-implementing code-secure's server, or any bridge to it.
- Changing finding identity (stays fingerprint-based).
- New scanners (we already have more than they do).

## 6. Cross-references
- Branch model: `finding_branch_occurrences` (mig 000173); ingest `internal/app/ingest/processor_findings.go` (occurrence write) + `service.go` (default-branch + full-coverage auto-resolve gate).
- Gate: `agent/internal/gate/security.go` (risk-aware, Phase 1).
- CI pipeline: `sdk-go/pkg/{gitenv,handler}`, agent `main.go runOnce`.
- Related: RFC-006 (per-tenant SCM/ticketing resolver), RFC-007 (coverage), prioritization (EPSS/KEV/VPR).
