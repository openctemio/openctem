# OpenCTEM Platform Architecture — CTEM 5-Stage Workflow

> This document describes how OpenCTEM implements the 5 CTEM stages per the ctem.org framework,
> which features map to each stage, and how they connect end-to-end.

## Overview

CTEM (Continuous Threat Exposure Management) is Gartner's 5-stage operating model
for continuously reducing material cyber risk:

```
┌─────────┐   ┌───────────┐   ┌──────────────┐   ┌────────────┐   ┌──────────────┐
│ SCOPING │ → │ DISCOVERY │ → │PRIORITIZATION│ → │ VALIDATION │ → │ MOBILIZATION │
│         │   │           │   │              │   │            │   │              │
│ Define  │   │ Enumerate │   │ Rank by real │   │ Prove      │   │ Drive fixes  │
│ what to │   │ assets &  │   │ business     │   │ actual     │   │ to completion│
│ protect │   │ exposures │   │ risk         │   │ exploitab. │   │ & measure    │
└─────────┘   └───────────┘   └──────────────┘   └────────────┘   └──────────────┘
     ↑                                                                    │
     └───────────────── Iterative cycle (quarterly) ─────────────────────┘
```

**Key distinction from Vulnerability Management:**
CTEM answers "What exposures meaningfully increase the probability of a business-impacting incident?"
— not just "What CVEs do we have?"

---

## Stage 1: Scoping — "What to protect, and why?"

### Purpose
Define the assessment boundary: which assets matter most, what threat models apply,
and how to measure success. Scoping prevents CTEM from becoming an unbounded backlog.

### Features

| Feature | Description | Why it matters |
|---------|-------------|----------------|
| **CTEM Cycles** | Time-boxed assessment periods (planning → active → review → closed) | Measures improvement over time; prevents drift |
| **Scope Targets** | Pattern-based rules defining in-scope assets (19 target types) | Focuses discovery on what matters |
| **Business Units** | Organizational grouping of assets with risk aggregation | Maps assets to business context |
| **Crown Jewels** | High-impact assets marked with `is_crown_jewel` + business_impact_score | Drives P0 priority when threatened |
| **Attacker Profiles** | 4 threat model types: external, stolen creds, insider, supply chain | Defines what adversaries to test against |
| **Scope Exclusions** | Explicit out-of-scope rules with justification + expiration | Avoids noise, documents decisions |

### Workflow

```
1. Create CTEM Cycle → status: planning
2. Set charter (business priorities, risk appetite, objectives)
3. Link attacker profiles (threat model for this cycle)
4. Review/update scope targets and exclusions
5. Activate cycle → status: active, scope snapshot frozen
   ... run through Discovery → Prioritization → Validation → Mobilization ...
6. Start review → status: review
7. Close cycle → status: closed, metrics computed automatically
```

### Tables
`ctem_cycles`, `ctem_cycle_scope_snapshots`, `ctem_cycle_metrics`,
`ctem_cycle_attacker_profiles`, `attacker_profiles`,
`scope_targets`, `scope_exclusions`, `business_units`, `business_unit_assets`

---

## Stage 2: Discovery — "What do we own? What's exposed?"

### Purpose
Enumerate all assets within scope and identify exposures — not just CVEs, but also
misconfigurations, identity weaknesses, leaked credentials, and control gaps.

### Features

| Feature | Description | Why it matters |
|---------|-------------|----------------|
| **Asset Inventory** | 16 asset types with type-specific normalization and dedup | Know what you own |
| **Asset Relationships** | 16 relationship types (runs_on, depends_on, exposes...) | Map attack paths |
| **Finding Ingestion** | CTIS format, 17 source types, fingerprint-based dedup | Aggregate from multiple scanners |
| **Exposure Events** | 20+ event types (port changes, bucket exposure, credential leak...) | Track attack surface changes |
| **Data Quality Scorecard** | Asset ownership %, evidence %, freshness, dedup rate | Ensure data quality supports decisions |
| **IP Correlation** | Match hosts by IP across scanners for dedup | Reduce duplicate assets |

### Ingestion Pipeline

```
Agent scan → CTIS report → POST /api/v1/ingest
  → Step 1: Normalize asset name (16 type-specific handlers)
  → Step 2: IP correlation for host dedup
  → Step 3: Fingerprint dedup for findings
  → Step 4: Enrich with EPSS score + KEV status
  → Step 5: Classify priority P0-P3
  → Step 6: Persist to database
```

### Tables
`assets`, `findings`, `exposure_events`, `asset_relationships`,
`asset_merge_log`, `asset_dedup_review`

---

## Stage 3: Prioritization — "What to fix first?"

### Purpose
Rank findings by actual business risk — combining exploit evidence, reachability,
asset criticality, and compensating controls. NOT just by CVSS severity.

### Features

| Feature | Description | Why it matters |
|---------|-------------|----------------|
| **Priority Classes P0-P3** | P0=immediate, P1=urgent, P2=scheduled, P3=track | Clear action tiers with SLAs |
| **EPSS Enrichment** | Exploit Prediction Scoring System (0-100% probability) | "How likely is this to be exploited?" |
| **KEV Enrichment** | CISA Known Exploited Vulnerabilities catalog | "Is this already being exploited in the wild?" |
| **Override Rules** | Per-tenant configurable rules (e.g., KEV + reachable = P0) | Customize to organization's risk appetite |
| **Attack Path Scoring** | BFS reachability from internet entry points to crown jewels | "Can an attacker actually reach this?" |
| **Compensating Controls** | Security controls that reduce effective risk (WAF, segmentation...) | P1 downgrades to P2 if effective controls present |
| **Risk Scoring** | Configurable per-tenant: exposure x criticality x findings | Asset-level risk aggregation |

### Priority Classification Logic

```
P0: KEV + (reachable OR crown_jewel)
    "Actively exploited, attacker can reach it" → SLA: 7 days

P1: EPSS >= 10% + reachable + critical/high asset + no controls
    "High exploitation probability, important target" → SLA: 30 days

P2: Medium risk with controls, OR critical but unreachable
    "Notable risk but mitigated or contained" → SLA: 60 days

P3: Low risk, unreachable, or informational
    "Track and fix opportunistically" → SLA: 180 days
```

### Tables
`findings` (priority_class, epss_score, is_in_kev, is_reachable),
`priority_override_rules`, `priority_class_audit_log`,
`compensating_controls`, `sla_policies`

---

## Stage 4: Validation — "Can attackers actually exploit this?"

### Purpose
Prove that theoretical vulnerabilities pose genuine risk in your specific environment.
Test whether security controls detect and respond as designed.

### Features

| Feature | Description | Why it matters |
|---------|-------------|----------------|
| **Pentest Campaigns** | Full lifecycle: scope, execute, report, retest | Prove exploitation paths |
| **Pentest Findings** | PoC code, evidence, request/response capture | Engineering-grade proof |
| **Retests** | Verify fixes work (pending → passed/failed) | Confirm remediation effectiveness |
| **Attack Simulations** | Automated simulation with MITRE ATT&CK mapping | Continuous validation |
| **Control Tests** | Test security controls against frameworks (CIS, NIST, ISO) | "Do our defenses actually work?" |
| **Verification Checklist** | Structured closure criteria before marking verified | Prevent premature closure |

### Verification Checklist (gates verified/closed transition)

```
Required (all must be true):
  [x] Exposure cleared — no longer observable from attacker perspective
  [x] Evidence attached — proof of fix documented
  [x] Register updated — status updated in exposure register

Optional (NULL = not applicable):
  [ ] Monitoring added — alerting/SIEM rule for regression
  [ ] Regression scheduled — recurring check scheduled
```

### Tables
`pentest_campaigns`, `pentest_findings`, `pentest_retests`,
`attack_simulations`, `control_tests`, `finding_verification_checklists`

---

## Stage 5: Mobilization — "Drive fixes to completion"

### Purpose
Convert prioritized, validated findings into executed remediation with clear ownership,
enforceable SLAs, and measurable risk reduction — not just ticket creation.

### Features

| Feature | Description | Why it matters |
|---------|-------------|----------------|
| **SLA Policies** | Deadlines by severity + priority class (P0=7d, P1=30d...) | Enforceable accountability |
| **SLA Escalation** | Auto-detect overdue findings, mark breached, notify | No findings slip through cracks |
| **Remediation Campaigns** | Group findings, track progress, measure risk before/after | Outcome-based tracking |
| **Jira Integration** | Create tickets from findings, severity to priority mapping | Meet teams where they work |
| **Approval Workflow** | Risk acceptance with expiration, self-approval prevention | Governance of residual risk |
| **Risk Trend Metrics** | Daily snapshots: risk score, MTTR, SLA compliance, P0-P3 | Executive reporting |

### Outcome Metrics (not activity metrics)

| Category | Metric | Source |
|----------|--------|--------|
| **Speed** | MTTR for validated P0/P1 exposures | risk_snapshots.mttr_critical_hours |
| **Quality** | Regression rate (remediated findings reappearing) | findings.status transitions |
| **Risk Reduction** | Reduction in reachable exposure to crown jewels | risk_snapshots.p0_open trend |
| **Governance** | SLA compliance rate | risk_snapshots.sla_compliance_pct |
| **Coverage** | % crown jewels + identities in CTEM scope | data quality scorecard |

### Tables
`sla_policies`, `remediation_campaigns`, `risk_snapshots`,
`notification_outbox`, `finding_status_approvals`

---

## Background Controllers

| Controller | Interval | Purpose |
|-----------|----------|---------|
| `threat-intel-refresh` | 24h | Sync EPSS scores + KEV catalog from FIRST.org and CISA |
| `sla-escalation` | 15m | Detect overdue findings, mark as breached, trigger notifications |
| `risk-snapshot` | 6h | Compute daily risk/MTTR/SLA/priority metrics per tenant |
| `approval-expiration` | 1h | Expire time-bound risk acceptances |
| `scan-retry` | 5m | Retry failed scans with exponential backoff |
| `agent-health` | 1m | Monitor agent heartbeats, mark unhealthy |

---

## Database Schema Summary (148 migrations)

```
Scoping (Stage 1):
  ctem_cycles, ctem_cycle_scope_snapshots, ctem_cycle_metrics,
  ctem_cycle_attacker_profiles, attacker_profiles,
  scope_targets, scope_exclusions, scan_schedules,
  business_units, business_unit_assets

Discovery (Stage 2):
  assets, findings, exposure_events, exposures,
  asset_relationships, asset_merge_log, asset_dedup_review,
  epss_scores, kev_catalog, threat_intel_sync_status

Prioritization (Stage 3):
  priority_override_rules, priority_class_audit_log,
  compensating_controls, compensating_control_assets, compensating_control_findings,
  sla_policies

Validation (Stage 4):
  pentest_campaigns, pentest_findings, pentest_retests,
  attack_simulations, attack_simulation_runs, control_tests,
  finding_verification_checklists

Mobilization (Stage 5):
  remediation_campaigns, finding_status_approvals,
  notification_outbox, notification_events,
  risk_snapshots, audit_logs
```

---

## References

- [ctem.org — Getting Started](https://ctem.org/docs/getting-started)
- [ctem.org — 5 Stages](https://ctem.org/docs/stages/)
- [ctem.org — CTEM vs Vulnerability Management](https://ctem.org/docs/comparisons/ctem-vs-vulnerability-management)
- [FIRST EPSS](https://www.first.org/epss)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

*Last updated: 2026-04-15 — RFC-004 + RFC-005 implemented*
