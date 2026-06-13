# OpenCTEM — Feature Ideas & Opportunity Backlog

> Companion to [`ROADMAP.md`](./ROADMAP.md). ROADMAP says *what we commit to next
> and why*; this doc is the wider **idea pool**: a full-surface feature audit
> (shipped / half-built / missing) plus a large set of grounded proposals to
> mine from. Generated 2026-06-12 from a five-cluster code survey. Each idea
> notes rough effort (S/M/L) and the existing code it builds on, so nothing here
> is greenfield hand-waving.

## How to read this

- **§1 Reality check** — corrections to common misconceptions, so we plan from
  the true state of the tree.
- **§2 "Make it real" backlog** — features that *look* done but aren't wired
  end-to-end. Highest ROI: we already paid for the hard parts.
- **§3 New-feature ideas by cluster** — the idea pool.
- **§4 The next ten** — a suggested ordering.

---

## 1. Reality check (true state, 2026-06-12)

Several things are further along (or further behind) than they look:

- **Report scheduler** — DONE end-to-end (controller polls `ListDue` → renders
  `GenerateSummaryHTML` → emails → records next run). Shipped in api#177. *Not*
  broken. Remaining: PDF + technical/compliance generators.
- **Risk-posture trending** — DONE. `risk_snapshots` (migration 000145),
  `RiskSnapshotController` (registered, 6h), `/dashboard/risk-trend` +
  `/velocity`, UI charts. No further core work needed.
- **Remediation campaign progress** — DONE in api#179: live finding counts from
  the `finding_filter`, 30-min reconcile controller, auto-complete. Was
  previously cosmetic (always 0%). Remaining: campaign→Jira-**epic** sync.
- **Jira outbound status sync** — has an echo-guard (`SyncFindingStatusToTicket`
  reads `GetIssueStatus` and skips if already at target; falls back to a comment
  when no transition exists). It is opt-in (`mapping.SyncEnabled`, default off).
- **SSO** — OIDC SSO **exists** (`internal/app/auth/sso.go`, per-tenant provider,
  auto-provision, Okta-tested) plus OAuth (Google/GitHub/Microsoft). The gap is
  **SAML + SCIM + LDAP**, not "no SSO".

---

## 2. "Make it real" backlog — finish the half-built (highest ROI)

These are features with a UI and/or schema and/or domain methods already in
place but **not wired end-to-end**. Verified against the tree.

### 2.1 Reachability is never populated → prioritization input is dead ⚠️ (correctness)
`Finding.SetReachability()` exists and P0–P3 classification reads
`ctx.IsReachable || ctx.IsInternetAccessible` (`pkg/domain/vulnerability/priority.go:84`),
but **no ingest/service path ever calls `SetReachability`** — the fields are
always their zero value. So "reachable" never contributes to priority, and the
KEV-or-exploit-and-reachable → P0 rule effectively degrades to KEV-or-exploit.
**Fix (M):** populate reachability at ingest — internet-accessible from the
asset's exposure/port data; network-accessible from asset class. Even a coarse
"asset is internet-facing → finding is internet-accessible" pass makes the
existing rule honest. Builds on: asset exposure data, `SetReachability`,
priority engine.

### 2.2 Validation engine (the "V" in CTEM) — CRUD without execution (L)
`/api/v1/simulations` and `/api/v1/control-tests` have full CRUD + a `/run`
endpoint, schema (`control_tests`, `attack_simulation_runs`), and a designed
`internal/app/validation/executor.go` (types + selector + attacker-profile
gate). What's missing is the **engine**: dispatch a sim/control-test to the
agent platform-jobs queue → agent runs the safe-check/atomic-red-team driver →
evidence POSTed back → correlated to control coverage / finding status.
**Build (L):** `ValidationDispatcher` (queue bridge) + `/validation/evidence`
ingest + result correlation + agent-side drivers. This is the single biggest
product-narrative gap — we sell CTEM (Scoping→…→**Validation**→Mobilization) but
Validation is mostly data models. Builds on: validation types, platform-jobs
queue, control-test schema, agent executor router.

### 2.3 Backend-complete features with no UI (M total, several S each)
Each has a full API and zero UI — operators must use curl:
- **Scanner templates** (`/api/v1/scanner-templates`) — upload/manage custom
  Nuclei/Semgrep/Gitleaks rules.
- **Template sources** (`/api/v1/template-sources`) — Git/S3/HTTP rule repos.
- **Secret store** (`/api/v1/secret-store`) — tokens used by template sources.
- **Asset dedup review** (`/api/v1/assets/dedup/reviews`) — RFC-001 admin merge
  queue.
- **Scan profile quality gates** — `EvaluateQualityGate` exists; no config form.
**Build (S each):** standard list/detail/form screens; the hooks pattern is
well-established in the UI. Builds on: existing handlers + UI feature-folder
convention.

### 2.4 Agent executors declared but never registered (S)
`Router.RegisterAssets` and `Router.RegisterPipeline` exist but `platform.go`
never calls them (only VulnScan/Secrets/Recon/Tenable are wired); Trufflehog is
a config flag with no implementation (`internal/executor/secrets.go`). Either
wire them or remove the dead surface. Builds on: executor router.

### 2.5 PDF / multi-format report output (M)
`pkg/report` emits HTML only; the scheduler labels technical/compliance as
"unsupported". Add a pluggable renderer (HTML → PDF via headless Chromium or
wkhtmltopdf; JSON for tooling). Compliance buyers expect a PDF attachment.
Builds on: `GenerateSummaryHTML`, report scheduler.

---

## 3. New-feature idea pool (by cluster)

Curated and de-duplicated from the survey. Effort is rough; "builds on" is the
existing seam.

### 3.1 Scoping & Discovery
1. **Asset discovery timeline** (M) — per-asset provenance view (first seen, by
   which tool/source, type/status changes, merges). Builds on: `asset_state_history`.
2. **Scan compatibility threshold/gate** (S) — "require N% compatible / block if
   none" instead of advisory-only. Builds on: smart filtering.
3. **Scan coverage forecasting** (M) — "at this rotation we cover 3000 IPs in X
   weeks" + what-if batch sizing. Builds on: `CoverageScheduler`, `last_scanned_at`.
4. **Dynamic asset-group rules** (M) — auto-populate groups from boolean rules on
   tags/discovery/metadata. Builds on: scope rules + asset query filters.
5. **Scan dry-run / preview** (S) — resolve+filter assets, show "will scan N",
   then confirm — catch mis-scoped 10k-job scans. Builds on: filtering + trigger.
6. **Discovery-source filter in scan creation** (M) — "scan only assets from
   Tenable / discovered last 7d". Builds on: discovery-source tracking.
7. **Scanner capability heat-map** (M) — tool × asset-type coverage, surfaces
   tooling gaps. Builds on: `TargetMappingRepository` + asset-type counts.
8. **Platform-agent autoscaling hints** (M) — "add 5 agents to meet SLA" from
   queue depth + processing time. Builds on: `PlatformStats` + queue depth.

### 3.2 Prioritization & Validation
9. **Risk-score explainability API/UI** (M) — `/findings/{id}/scoring-breakdown`
   returning the factors + weights + confidence behind a P-class (the `Reason`
   is computed but never exposed). Table-stakes vs Wiz/Tenable VPR. Builds on:
   `PriorityContext` + `ClassifyPriority`.
10. **What-if priority simulator** (L) — "if I add control X / if this CVE goes
    KEV, what's the new priority / blast radius?" The engine is deterministic;
    feed it a synthetic context. Builds on: classification engine.
11. **Compensating-control recommendation** (M) — "P0, but isolate it and it's
    P2" — suggest the cheapest control that lowers the class. Builds on:
    compensating-control reduction factors.
12. **Priority-rule sandbox / A-B** (M) — test a new rule against the historical
    finding corpus before enabling; show the P-class delta. Builds on:
    `PriorityRuleRepository` + priority audit log.
13. **IOC → priority auto-escalation** (M) — a finding matched to an APT actor in
    the IOC catalogue auto-bumps priority + flags the threat team. Builds on: IOC
    catalogue + match log + reclassify pipeline.
14. **Finding dedup confidence scoring** (M) — score "same CVE on A and B = one
    finding?" and auto-merge high-confidence, queue the rest. Builds on: asset
    dedup (RFC-001) extended to findings.
15. **Category-level risk aggregation** (M) — risk by vector (network/app/data/
    identity/cloud) with drill-down — the executive view. Builds on: finding
    vectors + risk fields.

### 3.3 Mobilization, Integrations & Reporting
16. **Remediation campaign → Jira epic sync** (M) — push a campaign to a Jira
    **epic**, reflect epic status back; the finding-level sync already exists.
    Completes Tier-1 #2. Builds on: `jira.SyncService`, RFC-006 Phase 3e WorkItem
    seam. *(Designed; the immediate next build.)*
17. **GitHub Issues as a 2nd ticket provider** (M) — copy the Jira pattern over
    the existing GitHub SCM client; validates the provider abstraction. Builds
    on: `scm.ClientFactory`, `jira.SyncService` shape.
18. **Scheduled digest notifications** (M) — daily/weekly roll-up ("5 critical
    opened, 3 closed, 2 campaigns done") to Slack/Teams/email; cuts alert
    fatigue. Builds on: notification outbox + schedule domain.
19. **Remediation campaign SLA + escalation** (M) — attach an SLA policy to a
    campaign due date; auto-escalate overdue. Builds on: campaign domain + the
    finding SLA infra.
20. **Campaign burndown + projected close** (S) — `/campaigns/{id}/progress?
    granularity=daily` time series + linear projection. Builds on: campaign
    reconcile (now persists counts each tick — add history).
21. **Slack thread grouping** (S) — group a burst of findings under one thread
    instead of N messages. Builds on: outbox + Slack client.
22. **Automated remediation-campaign rules** (L) — "high SCA finding → auto-open
    a 'deps' campaign for the backend team". Builds on: campaign service +
    assignment-rule pattern.
23. **Audit-log → SIEM webhooks** (S) — stream audit events to Splunk/ELK in
    real time. Builds on: notification multi-channel delivery.

### 3.4 Shift-left agent & CI/CD
24. **Auto-fix PRs** (M) — SCA finding with a fixed version → open a dependency-
    bump PR; secret committed → PR with placeholder + rotation guide. The
    differentiator vs code-secure. Builds on: SCA parsing, PR-comment machinery,
    branch-aware lifecycle.
25. **SBOM + license-compliance gate** (M) — Trivy SBOM → CycloneDX export; gate
    on GPL/AGPL/proprietary deps in a PR. Builds on: Trivy scanner + gate framework.
26. **Reachability-aware SAST filtering** (L) — use Semgrep dataflow to drop
    findings in unreachable code paths. Builds on: Semgrep dataflow + fingerprints.
27. **Baseline-management UI** (M) — approve findings as tech-debt/intentional,
    reset per-branch baseline, mute rules. Builds on: `finding_branch_occurrences`.
28. **Monorepo workspace scoping** (M) — scan + comment only the touched
    package/workspace in a PR. Builds on: changed-file scoping.
29. **IDE plugins (VS Code/JetBrains)** (L) — inline Semgrep/Gitleaks while
    editing with suppression quick-fixes. Builds on: scan engine / agent API.
30. **Secret entropy scoring** (S) — gate only high-entropy secrets to cut
    false positives on fake keys. Builds on: gitleaks integration + gate rules.

### 3.5 Platform / Enterprise
31. **SAML 2.0** (M) — alongside OIDC for legacy IdPs / air-gapped orgs. Builds
    on: the existing IdP-provider abstraction in `sso.go`.
32. **SCIM 2.0 provisioning** (L) — auto provision/deprovision from Azure AD /
    Okta / Google; revoke on termination. Builds on: user CRUD + invitation
    role-assignment.
33. **Usage analytics / metering** (M) — per-tenant API calls, storage, scan
    minutes, agent utilization — ROI + chargeback. Builds on: `PlatformStats`
    pattern + async logging.
34. **Billing & quotas** (L) — Stripe, usage meter, per-tenant quotas + overage.
    Permissions (`settings:billing:*`) already exist but are unguarded. Builds
    on: permission system + settings module.
35. **Custom-role builder UI** (S) — `RoleService.Create/Update/Delete` exist
    (Enterprise edition); add the permission-picker UI. Builds on: RBAC catalog.
36. **Compliance evidence export + readiness score** (M) — map controls→passing
    tests, export signed SOC2/ISO27001 attestation. Builds on: compliance
    assessment mappings + audit chain.
37. **API rate-limit tiers** (S) — free/pro/enterprise limits keyed off the plan
    claim. Builds on: existing per-tenant limiter + permission cache.
38. **White-label** (M) — custom domain, email sender, report branding, theme.
    Builds on: tenant settings (`LogoURL` exists) + SMTP resolver.
39. **i18n translation layer** (M) — the locale/RTL scaffold exists (en/vi/ar)
    but no catalog is wired; add react-i18next + a string catalog (vi first).
    Builds on: `lib/i18n.ts`.
40. **Session/device management** (S) — "logged in from Chrome/macOS/NYC", revoke
    by device; "log out all other devices". Builds on: session service + audit.

---

## 4. The next ten (suggested order)

Balancing ROI, narrative completeness, and reuse of existing infra:

1. **Reachability population** (§2.1) — fixes a dead prioritization input; small,
   high-integrity.
2. **Remediation campaign → Jira epic** (§3, #16) — finishes Tier-1 #2.
3. **Risk-score explainability** (§3, #9) — competitive table-stakes; the data
   already exists.
4. **GitHub Issues provider** (§3, #17) — validates the ticket abstraction; large
   audience.
5. **PDF report output** (§2.5) — unblocks compliance reporting.
6. **Scheduled digest notifications** (§3, #18) — daily value, cuts alert fatigue.
7. **Backend-only admin UIs** (§2.3) — cheap wins; stops "curl-only" features.
8. **Validation engine MVP** (§2.2) — start the dispatcher + evidence ingest;
   the biggest narrative gap.
9. **Auto-fix PRs for SCA** (§3, #24) — the shift-left differentiator.
10. **SAML + custom-role UI** (§3, #31/#35) — enterprise procurement unblockers.

> Update this doc as ideas graduate into `ROADMAP.md` or ship.
</content>
</invoke>
