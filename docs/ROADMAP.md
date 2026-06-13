# OpenCTEM — Project Assessment & Roadmap

> Living strategic doc: where the platform stands, where it's strong, and the
> prioritized work to make it best-in-class. Updated 2026-06-12.

## 1. What OpenCTEM is

A multi-tenant **CTEM** (Continuous Threat Exposure Management) platform that
operationalizes AppSec across the SDLC. The sidebar mirrors the five CTEM phases:
**Scoping → Discovery → Prioritization → Validation → Mobilization**. The
differentiator vs. a plain scanner: *correlate + dedup → business-context
prioritize → validate → mobilize*, not just "list findings".

## 2. Honest assessment — strengths (verified)

Three rounds of cross-repo deep-dive + a competitive study (califio code-secure)
back these up:

- **Multi-tenant isolation** is correct end-to-end (`WHERE tenant_id` everywhere;
  cache keys tenant-scoped; ingest tenant from the authenticated agent).
- **Risk prioritization** beyond severity: EPSS + CISA-KEV + VPR + reachability +
  asset criticality. Most scanners stop at severity.
- **Shift-left agent** is peer/ahead of code-secure: multi-scanner, risk-aware
  gate, idempotent PR/MR comments + sticky summary, **new-vs-base** PR scoping.
- **Mobilization**: bidirectional Jira sync (create + inbound + outbound status,
  opt-in, echo-safe), per-tenant configurable status maps.
- **Reliability**: transactional outbox + asynq queues, `FOR UPDATE SKIP LOCKED`,
  audit hash-chain, paired migrations, preflight-migrate gate.
- **Code-level security**: across ~9 reviewer-passes only ~8 genuine bugs surfaced
  (all fixed); auth/JWT/permission swept clean. The base is solid.

## 3. Honest assessment — gaps (where value is thin)

The engine is strong; the **operator/management layer** that customers see weekly
is thin:

- **Reporting**: scheduler controller now runs `ListDue()` end-to-end (#177);
  remaining gaps are PDF export and technical/compliance report generators.
  *(Core scheduler done — see Tier 1.)*
- **Remediation workflow**: findings can become Jira tickets, but there's no
  first-class *remediation campaign* (group findings → owner → deadline →
  progress) — the core Mobilization narrative. **This is the main open Tier-1
  item.**
- **Ticketing breadth**: Jira only (provider abstraction exists, unused).
- **Enterprise table-stakes**: no SSO/SAML; i18n framing exists (en/vi/ar
  direction) but no translation layer wired.
- Operational debt: `.sc` active-IP accounting deferred; live Nessus REST only
  mock-verified; dependency drift between develop/main (self-healing via
  retargeted dependabot).

## 4. Prioritized roadmap

Ordered by value-to-effort. Tier 1 builds entirely on existing infra (no new
infrastructure, no product unknowns).

### Tier 1 — finish what's promised (highest ROI)

1. **Report scheduler + weekly digest** ✅ *(core shipped)* — `report_schedules`
   now execute. Pieces delivered: generic exec-summary generator
   (`pkg/report.GenerateSummaryHTML`, #175) → `ReportScheduler` controller polling
   `ListDue` + rendering + email delivery + `RecordRun` + next-run via
   `robfig/cron` (#177). *Remaining polish:* PDF export, technical/compliance
   report generators, KEV/EPSS/SLA breakdown in the digest (needs extra queries —
   `FindingStats` has no KEV/EPSS fields today).
2. **Remediation Campaigns (`remediation_task`)** ⟵ **next** — group N findings
   into a task with owner / deadline / progress, **bidirectional Jira sync via the
   `WorkItem` seam already designed in RFC-006 Phase 3e**. Completes the
   Mobilization pillar and is literally the "create a task that syncs to Jira" ask.
   This is the remaining open Tier-1 item.
3. **Risk-posture trending** ✅ *(already shipped)* — `risk_snapshots` table
   (migration 000145), `RiskSnapshotController` (registered in `workers.go`, 6h
   interval), `GET /dashboard/risk-trend` + `/velocity` endpoints, and UI trend
   charts already exist. No further work required beyond surfacing the series in
   scheduled reports (see #1 polish).

### Tier 2 — broaden reach

4. **GitHub Issues as a 2nd ticket provider** — cheap (the `TicketProvider`
   interface exists), large audience, validates the abstraction.
5. **Agent auto-fix PRs** — for SCA findings with a fixed version, the agent opens
   a dependency-bump PR. A strong shift-left differentiator beyond code-secure.
6. **Finish RFC-007** — `.sc` active-IP accounting + live-appliance Nessus REST
   verification (needs real hardware).

### Tier 3 — commercial foundation

7. **SSO / SAML** — enterprise procurement table-stakes.
8. **i18n translation layer** — the direction/RTL scaffold exists; wire a real
   string catalog (notably for the vi market).
9. **Compliance packs** — map findings → ISO 27001 / PCI / SOC2 controls
   (compliance finding-type already exists) → audit-ready evidence.

## 5. Recommendation

With Tier-1 #1 (report scheduler) and #3 (risk trending) shipped, the remaining
highest-ROI item is **#2 Remediation Campaigns** — the one piece that turns
"findings → tickets" into a managed Mobilization workflow. Build it next, then
move to Tier 2 (GitHub Issues provider, agent auto-fix PRs).

## 6. Cross-references

- RFC-006 (ticketing + bidirectional sync), RFC-007 (scan coverage), RFC-008
  (shift-left CI). Architecture docs under `docs/architecture/`.
- This doc is the index for "what to build next and why"; update it as Tier items
  ship.
