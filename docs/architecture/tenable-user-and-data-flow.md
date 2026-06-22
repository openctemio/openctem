# Tenable — User Flow & Data Flow

How an operator interacts with Tenable (Nessus Pro / Tenable.sc) in OpenCTEM, and
how data moves end-to-end. Companion to
[Scan Coverage](scan-coverage.md) and [RFC-007](../rfcs/RFC-007-license-aware-scan-coverage.md).

> **Status legend:** ✅ shipped · 🔜 planned (RFC-007 Phase 2–4). The current
> working path is **manual `.nessus` ingest**; the rich connect/coverage UI and
> the live runner are planned. This doc describes the intended UX *and* what
> works today.

---

## 1. Where Tenable lives in the UI

```
Settings → Integrations → Security        → connect/manage Tenable (engine + mode)   🔜 dialog (api ready ✅)
Discovery → Scan Coverage                 → coverage rotation + freshness/license     🔜
Exposures / Findings                      → Tenable findings appear here like any other ✅
Assets                                    → hosts discovered by Tenable scans          ✅
```

Tenable is a **security-category integration** (`provider=tenable`). Its findings
and assets flow into the same Findings/Assets/Exposures screens as every other
source — no separate silo.

---

## 2. User flow A — Configure a Tenable integration  (api ✅ / UI 🔜)

The operator creates one integration per Tenable instance and chooses **how
OpenCTEM reaches it**:

```
Add integration → provider: Tenable
  ├─ Engine:          ( ) Nessus Professional   ( ) Tenable.sc
  ├─ Execution mode:  (•) Agent (runner)        ( ) Direct (backend → Tenable)
  ├─ Base URL:        https://<nessus-or-sc-host>        [direct only / optional for agent]
  └─ Credentials:     ┌──────────────────────────────────────────────┐
                      │ AGENT mode  → field HIDDEN. Creds live on the │
                      │   runner in the prod zone, never sent here.   │
                      │ DIRECT mode → access key + secret key required│
                      └──────────────────────────────────────────────┘
```

**The UX must mirror the server rule** (already enforced — `internal/app/scancoverage/tenable_config.go`):

| Mode | Credentials field | Server rule (enforced) |
|------|-------------------|------------------------|
| **Agent** (default, recommended) | **hidden / not collected** | rejecting creds — they belong on the runner (RFC-007 §8 R3/R4) |
| **Direct** (optional) | required (access + secret key) + base URL | creds encrypted (AES-256-GCM), api calls Tenable |

The create request carries the choice in `config`:

```jsonc
POST /api/v1/integrations
{ "name": "Corp Tenable", "category": "security", "provider": "tenable",
  "auth_type": "api_key",
  "config": { "execution_mode": "agent", "engine": "tenable_sc" } }   // agent → NO credentials
```

Unknown `execution_mode`/`engine` are rejected; the stored record is normalized to
explicit values. The same rule is enforced on **update** (can't add creds to an
agent-mode integration later).

---

## 3. User flow B — Get scan results into OpenCTEM

### B1. Manual / cron `.nessus` upload  ✅ (works today)

The pragmatic path that works now (no runner needed): export a `.nessus` from
Nessus/.sc and upload it (a person, or a cron job on the prod network):

```
Findings/Assets → Import → Nessus results        🔜 (button)
  └─ POST /api/v1/assets/import/nessus-findings   ✅ (endpoint live)
        ?session_id=<batch>  &tool=tenable  &min_severity=1
        body: the .nessus XML
```

Each upload = one **batch/session**: assets + vulnerability findings are ingested,
and stale Tenable findings on the uploaded hosts are auto-resolved **scoped to
that batch only**.

### B2. Runner-mediated (polling) — the default model  🔜

The operator configures a **runner** in the prod zone (alongside Nessus/Tenable).
OpenCTEM never reaches the appliance; the runner polls OpenCTEM for jobs and
pushes results. (See §5 for the data flow.) From the operator's view:

```
Discovery → Scan Coverage → New coverage plan
  ├─ Scope:        asset group / tag (e.g. "all corp hosts" = 3000)
  ├─ Engine/mode:  (from the Tenable integration)
  ├─ Batch size:   500 (license headroom)         [.sc only]
  ├─ Cadence:      weekly full sweep / criticality-weighted
  └─ Runner:       <tenant runner in prod zone>
```

OpenCTEM then drives the rolling coverage automatically (§5).

---

## 4. User flow C — See & act on results  ✅

Tenable findings are first-class CTIS findings, so they appear wherever findings
do, carrying the data the converter now maps to first-class fields:

- **Severity** (Nessus 0–4 → info…critical), **CVE(s)** (`cve_ids` + primary),
  **CVSS** (v3 preferred), **Tenable VPR**, **exploit available**, **CPE**.
- **Network location** — the port/protocol/service the finding sits on.
- **Evidence** — the Nessus plugin_output.
- **Remediation** — the Nessus solution.

Prioritisation (RFC-004), ticketing/Mobilization (RFC-006), SLA, and auto-reopen
all apply to Tenable findings like any other source.

---

## 5. Data flow

### 5a. Runner-mediated (polling) — DEFAULT  🔜

```
┌── PROD zone ─────────────────────────────────┐         ┌── CONTROL zone ─────────────┐
│  OpenCTEM runner                              │         │  OpenCTEM api               │
│    holds Tenable creds (local) ──► Nessus/.sc │         │  holds NO scanner creds     │
│        ▲ launch/poll/export(.nessus)/reclaim  │         │                             │
│        │                                      │ outbound│  1. scheduler picks batch B │
│  2. poll job ◄────────────────────────────────┼─────────┤     for session S (planner) │
│  3. run scan on B → .nessus → CTIS report     │  only   │                             │
│  4. PushCTIS(report, metadata.id=S) ──────────┼────────►│  5. ingest pipeline:        │
│  7. on ACK: reclaim B (free .sc cap) ─────────┼────────►│     - upsert assets/findings│
│     report reclaim via job result             │         │     - AutoResolveStale(B,S) │
└───────────────────────────────────────────────┘         │  6. ACK + mark B scanned,   │
   only OUTBOUND crosses the zone boundary                 │     free active_ip_set,     │
                                                           │     advance cursor          │
                                                           └─────────────────────────────┘
```

- Transport reuses the existing platform-agent machinery (register → lease →
  `POST /platform/poll` → job `ack`/`progress`/`result` + `PushCTIS`).
- `session_id` (S) is the join key: it scopes auto-resolve and correlates results.
- The runner owns reclaim (only it reaches the appliance); the api scheduler stays
  authoritative for dispatch + the `.sc` active-IP cap.

### 5b. Direct — OPTIONAL (cloud / reachable `.sc`)  🔜

```
api (DirectRunner) ──► resolve per-tenant Tenable creds (ListByProvider(tenant))
   └─ TenableClient.Launch(B) → poll → Export(.nessus) → parse → ingest(session=S) → reclaim
```

Same pipeline below the boundary; the api holds creds and calls Tenable directly.
Only for deployments that accept api↔Tenable.

### 5c. Manual `.nessus` upload — SHIPPED TODAY  ✅

```
operator/cron ──► POST /assets/import/nessus-findings (JWT, tenant from token)
   └─ nessus.Convert(.nessus) → *ctis.Report (tool=tenable, session=upload id)
        └─ ingest pipeline → assets + findings + batch-scoped auto-resolve
```

### Shared ingest core (all three paths)

```
.nessus ──► nessus.Convert ──► CTIS report ──► ingest.Service.Ingest(agt, report)
   tool=tenable · metadata.id=session · coverage=full · synthetic default branch
        ├─ assets upserted (correlator dedups hosts by IP/RFC-001)
        ├─ findings upserted (dedup by fingerprint nessus:<host>:<plugin>:<port>/<proto>)
        └─ AutoResolveStaleByAssets(tenant, assetIDs=batch, tool=tenable, scanID=session)
              → only this batch's stale Tenable findings are resolved; never other
                batches, never other tools' findings
```

---

## 6. Tenant isolation (every path)

- **agent**: the runner belongs to a tenant; jobs route only to that tenant's
  runner; pushed CTIS derives tenant from the **authenticated agent**, never the
  `.nessus` file. Creds never leave the prod zone, never cross tenants.
- **direct**: per-tenant resolver — `ListByProvider(tenantID, ProviderTenable)`
  (`WHERE tenant_id=$1`) → a tenant only ever uses its own creds.
- **upload**: tenant comes from the JWT only; the file cannot specify a tenant.

---

## 7. What's shipped vs planned

| Capability | Status |
|------------|--------|
| `.nessus → CTIS` converter (cve_ids/vpr/network/evidence) | ✅ |
| Manual `.nessus` ingest endpoint (batch-scoped auto-resolve) | ✅ (API; UI button 🔜) |
| Tenable integration config (engine/mode) + agent-mode no-creds security (create+update) | ✅ |
| License-aware batch planner (headroom + selection) | ✅ (core; scheduler 🔜) |
| Tenable connect dialog (engine/mode, hide creds in agent) | 🔜 (api ready) |
| Runner `tenable` tool + AgentRunner dispatch | 🔜 (Phase 2c) |
| Direct-mode `TenableClient` | 🔜 (Phase 2c, optional) |
| Coverage scheduler (rotation/cap/reclaim) | 🔜 (Phase 3) |
| Coverage UI (freshness, license utilisation, sweep cadence) | 🔜 (Phase 4) |
