# OpenCTEM Platform Architecture — CTEM 5-Stage Workflow

> Tài liệu này mô tả cách OpenCTEM thực hiện 5 giai đoạn CTEM theo framework ctem.org,
> các tính năng tương ứng, và cách chúng kết nối với nhau.

## Tổng quan

CTEM (Continuous Threat Exposure Management) là operating model 5 giai đoạn:

```
┌─────────┐   ┌───────────┐   ┌──────────────┐   ┌────────────┐   ┌──────────────┐
│ SCOPING │ → │ DISCOVERY │ → │PRIORITIZATION│ → │ VALIDATION │ → │ MOBILIZATION │
│         │   │           │   │              │   │            │   │              │
│ Xác định│   │ Phát hiện │   │ Xếp hạng ưu │   │ Xác minh   │   │ Thực hiện    │
│ phạm vi │   │ tài sản & │   │ tiên theo    │   │ khả năng   │   │ khắc phục    │
│ đánh giá│   │ lỗ hổng   │   │ rủi ro thực  │   │ khai thác  │   │ đo lường     │
└─────────┘   └───────────┘   └──────────────┘   └────────────┘   └──────────────┘
     ↑                                                                    │
     └────────────────── Cycle lặp lại (quarterly) ──────────────────────┘
```

## Stage 1: Scoping — "Đánh giá gì, cho ai?"

### Mục đích
Xác định phạm vi đánh giá: tài sản nào quan trọng, threat model nào áp dụng,
đo lường thành công bằng gì.

### Tính năng

| Feature | Mô tả | Tại sao cần |
|---------|-------|-------------|
| **CTEM Cycles** | Đợt đánh giá có thời hạn (planning→active→review→closed) | Đo improvement qua từng cycle, không đánh giá vô tận |
| **Scope Targets** | Pattern-based rules xác định tài sản nào in-scope (19 target types) | Tập trung vào attack surface quan trọng |
| **Business Units** | Nhóm tài sản theo tổ chức (Engineering, Security Ops...) | Map tài sản → business context |
| **Crown Jewels** | Đánh dấu tài sản quan trọng nhất (is_crown_jewel + business_impact_score) | Priority P0 khi crown jewel bị threat |
| **Attacker Profiles** | 4 mô hình threat: external, stolen creds, insider, supplier | Xác định threat model cho mỗi cycle |
| **Scope Exclusions** | Loại trừ tài sản/pattern khỏi scope với lý do | Tránh noise, tập trung resource |

### Luồng hoạt động

```
1. Tạo CTEM Cycle → status: planning
2. Set charter (business priorities, objectives)
3. Link attacker profiles (threat model)
4. Review scope targets
5. Activate → status: active, scope snapshot frozen
```

### Tables: `ctem_cycles`, `ctem_cycle_scope_snapshots`, `ctem_cycle_attacker_profiles`, 
`scope_targets`, `scope_exclusions`, `business_units`, `attacker_profiles`

---

## Stage 2: Discovery — "Có gì? Lỗ hổng ở đâu?"

### Mục đích
Phát hiện tất cả tài sản và exposure (không chỉ CVE — còn misconfig, secrets,
identity weakness, SaaS posture).

### Tính năng

| Feature | Mô tả | Tại sao cần |
|---------|-------|-------------|
| **Asset Inventory** | 16 asset types, normalization, IP correlation, dedup | Biết bạn có gì |
| **Asset Relationships** | 16 relationship types (runs_on, depends_on, exposes...) | Map attack paths |
| **Finding Ingestion** | CTIS format, 17 source types, fingerprint dedup | Tập hợp findings từ nhiều scanner |
| **Exposure Events** | 20+ event types (port_open, bucket_public, credential_leak...) | Track thay đổi attack surface |
| **Data Quality Scorecard** | Asset ownership %, evidence %, freshness, dedup rate | Đảm bảo data đủ tốt để ra quyết định |
| **Asset Normalization** | DNS lowercase, IP canonical, URL normalize... | Dedup chính xác |

### Luồng hoạt động

```
Agent scan → CTIS report → Ingest API
  → Normalize asset name (16 type handlers)
  → IP correlation (host dedup)
  → Fingerprint dedup (finding)
  → Enrich with EPSS/KEV
  → Classify priority P0-P3
  → Persist to DB
```

### Tables: `assets`, `findings`, `exposure_events`, `asset_relationships`, `asset_merge_log`

---

## Stage 3: Prioritization — "Fix cái nào trước?"

### Mục đích
Xếp hạng findings theo business impact + exploit likelihood + reachability,
KHÔNG chỉ theo CVSS severity.

### Tính năng

| Feature | Mô tả | Tại sao cần |
|---------|-------|-------------|
| **Priority Classes P0-P3** | P0=immediate, P1=urgent, P2=scheduled, P3=track | CTEM yêu cầu priority class, không chỉ severity |
| **EPSS Enrichment** | Exploit probability (0-100%) từ FIRST.org | "Likely to be exploited?" — CVSS không trả lời |
| **KEV Enrichment** | CISA Known Exploited Vulnerabilities catalog | "Already being exploited in the wild?" |
| **Override Rules** | Per-tenant rules: KEV+reachable+crown_jewel = P0 | Tùy chỉnh theo risk appetite |
| **Attack Path Scoring** | BFS reachability từ internet → crown jewels | "Can attacker actually reach this?" |
| **Compensating Controls** | Controls giảm risk: WAF, segmentation, MFA... | P1 → P2 nếu có control effective |
| **Risk Scoring** | Configurable per-tenant: exposure × criticality × findings | Asset-level risk score |

### Classification Logic

```
P0: KEV + (reachable OR crown_jewel)
    → "Đang bị exploit, phải fix ngay"
    → SLA: 7 ngày

P1: EPSS ≥ 0.1 + reachable + critical asset + no controls
    → "Rất có khả năng bị exploit, tài sản quan trọng"
    → SLA: 30 ngày

P2: Medium risk + có compensating controls
    HOẶC Critical severity nhưng unreachable
    → "Có risk nhưng đã có giải pháp tạm"
    → SLA: 60 ngày

P3: Low risk, unreachable, informational
    → "Track, fix khi có cơ hội"
    → SLA: Opportunistic
```

### Tables: `findings` (priority_class, epss_score, is_in_kev, is_reachable),
`priority_override_rules`, `priority_class_audit_log`, `compensating_controls`

---

## Stage 4: Validation — "Thực sự exploit được không?"

### Mục đích
Chứng minh findings thực sự có thể exploit trong môi trường cụ thể,
không chỉ "theoretically risky".

### Tính năng

| Feature | Mô tả | Tại sao cần |
|---------|-------|-------------|
| **Pentest Campaigns** | Full pentest lifecycle: scope, execute, report | Chứng minh exploit path |
| **Pentest Findings** | PoC code, evidence, request/response capture | Engineering-grade proof |
| **Retests** | Verify fix actually works (pending→passed/failed) | Đảm bảo fix hiệu quả |
| **Attack Simulations** | Automated simulation with MITRE ATT&CK mapping | Continuous validation |
| **Control Tests** | Test framework controls (CIS, NIST, ISO 27001) | "Do defenses work?" |
| **Verification Checklist** | Structured closure: exposure cleared, evidence, monitoring | Prevent premature closure |
| **MITRE Coverage** | Simulation coverage by tactic/technique | Gap analysis |

### Luồng hoạt động

```
Finding P0/P1 → Pentest campaign
  → Tester validates exploitability
  → Record evidence + PoC
  → Fix applied → Retest
  → Verification checklist:
    ☑ Exposure cleared
    ☑ Evidence attached  
    ☑ Register updated
    ☑ Monitoring added
    ☑ Regression scheduled
  → Mark verified/closed
```

### Tables: `pentest_campaigns`, `pentest_findings`, `pentest_retests`,
`attack_simulations`, `control_tests`, `finding_verification_checklists`

---

## Stage 5: Mobilization — "Ai fix? Bao giờ xong?"

### Mục đích
Chuyển findings thành action — assign owner, track SLA, enforce deadline,
đo outcome (risk reduction, không phải ticket count).

### Tính năng

| Feature | Mô tả | Tại sao cần |
|---------|-------|-------------|
| **SLA Policies** | Deadline theo severity + priority class | Accountability |
| **SLA Escalation** | Auto-detect overdue, mark breached, send notification | Enforce deadlines |
| **Remediation Campaigns** | Group findings → campaign, track progress, risk before/after | Measure outcome |
| **Jira Integration** | Create ticket from finding, severity→priority mapping | Meet teams where they work |
| **Approval Workflow** | Risk acceptance with expiration, self-approval prevention | Governance |
| **Risk Trend Metrics** | Daily snapshots: risk score, MTTR, SLA compliance, P0-P3 counts | Executive reporting |
| **Notification Outbox** | Multi-channel: Slack, Teams, Email, Webhook | Keep team informed |

### Outcome Metrics (không phải activity metrics)

```
Thay vì: "We closed 1,200 vulnerabilities"

Report: 
  "Eliminated 3 externally reachable paths to payment database (P0→0)
   Reduced P1 exposure in identity admin from 12 to 2 (83%)
   MTTR for validated exploitable findings: 5 days (down from 22)
   SLA compliance: 94% (up from 71%)"
```

### Tables: `sla_policies`, `remediation_campaigns`, `risk_snapshots`,
`notification_outbox`, `finding_status_approvals`

---

## Tổng quan Database Schema (148 migrations)

```
Scoping:
  ctem_cycles, ctem_cycle_scope_snapshots, ctem_cycle_metrics,
  ctem_cycle_attacker_profiles, attacker_profiles,
  scope_targets, scope_exclusions, scan_schedules,
  business_units, business_unit_assets

Discovery:
  assets, asset_relationships, asset_merge_log, asset_dedup_review,
  findings, exposure_events, exposures,
  epss_scores, kev_catalog, threat_intel_sync_status

Prioritization:
  priority_override_rules, priority_class_audit_log,
  compensating_controls, compensating_control_assets, compensating_control_findings,
  sla_policies

Validation:
  pentest_campaigns, pentest_findings, pentest_retests,
  attack_simulations, attack_simulation_runs, control_tests,
  finding_verification_checklists

Mobilization:
  remediation_campaigns, finding_status_approvals,
  notification_outbox, notification_events,
  risk_snapshots, audit_logs
```

## Background Controllers

| Controller | Interval | Mô tả |
|-----------|----------|-------|
| `threat-intel-refresh` | 24h | Sync EPSS + KEV từ FIRST.org/CISA |
| `sla-escalation` | 15m | Mark overdue findings as breached |
| `risk-snapshot` | 6h | Compute daily risk/MTTR/SLA metrics |
| `approval-expiration` | 1h | Expire time-bound risk acceptances |
| `scan-retry` | 5m | Retry failed scans |
| `agent-health` | 1m | Check agent heartbeats |

---

*Last updated: 2026-04-15 — RFC-004 + RFC-005 implemented*
