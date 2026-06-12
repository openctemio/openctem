# OpenCTEM — Project Assessment & Roadmap

> Living strategic doc: where the platform stands, where it's strong, and the
> prioritized work to make it best-in-class. Updated 2026-06-08.

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

- **Reporting**: schedules can be created in the UI but **never execute** (no
  controller runs `ListDue()`). PDF export missing. *(Being fixed — see Tier 1.)*
- **Remediation workflow**: findings can become Jira tickets, but there's no
  first-class *remediation campaign* (group findings → owner → deadline →
  progress) — the core Mobilization narrative.
- **Trending**: no historical risk-posture snapshots → can't answer "are we better
  than last month?", the question every CISO asks.
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

1. **Report scheduler + weekly digest** *(in progress)* — make `report_schedules`
   actually run. Pieces: generic exec-summary generator (`pkg/report.GenerateSummaryHTML`,
   shipped #175) → scheduler controller polling `ListDue` → deliver to recipients
   → `RecordRun` + next-run via `robfig/cron`. Default report content: findings by
   severity, KEV/EPSS counts, SLA breaches, new-vs-resolved, top risky assets.
2. **Remediation Campaigns (`remediation_task`)** — group N findings into a task
   with owner / deadline / progress, **bidirectional Jira sync via the `WorkItem`
   seam already designed in RFC-006 Phase 3e**. Completes the Mobilization pillar
   and is literally the "create a task that syncs to Jira" ask.
3. **Risk-posture trending** — a daily snapshot table (severity counts, open total,
   KEV count, avg risk) + one cron + one chart. Unlocks "trend over time" across
   dashboard, reports, and SLA.

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

Execute **Tier 1 in order (1 → 2 → 3)**. All three convert "good engine" into
"product an operator opens every morning", reuse existing infrastructure, and
need no new product decisions. Item 1 is underway (#175 + controller next).

## 6. Cross-references

- RFC-006 (ticketing + bidirectional sync), RFC-007 (scan coverage), RFC-008
  (shift-left CI). Architecture docs under `docs/architecture/`.
- This doc is the index for "what to build next and why"; update it as Tier items
  ship.
