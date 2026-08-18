# RFC Index & Feature-Thread Map

This is the map of design documents (RFCs) and how they connect to shipped PRs
and the code. Start here to remember "what was decided, why, and where it lives".

## RFC index

| RFC | Title | Status | Design PR | Implementation PRs |
|-----|-------|--------|-----------|--------------------|
| [RFC-001](RFC-001-asset-identity-resolution.md) | Asset identity resolution | Implemented | — | (2026-04 batch) |
| [RFC-002](RFC-002-decouple-api-from-sdk.md) | Decouple API from SDK-Go | Implemented | — | `feat/decouple-sdk` |
| [RFC-005](RFC-005-asynchronous-ingest.md) | Asynchronous ingest | Implemented | — | #123–#133 |
| [RFC-006](RFC-006-ticketing-provider-and-mapping.md) | Ticketing: provider abstraction + configurable mapping | Phase 0 done | #136 | #134, #135, **#137** + ui#152 |
| [RFC-007](RFC-007-license-aware-scan-coverage.md) | License-aware scan coverage (Tenable Nessus Pro + .sc) | Proposed, Phase 1 in progress | #138 | **#139** (converter) |
| [RFC-008](RFC-008-native-shift-left-ci-scanning.md) | Native shift-left CI/CD code scanning (agent-first) | Proposed, Phase 1 shipped | — | agent **#27** (risk-aware gate) |
| [RFC-009](RFC-009-enterprise-sso-saml-scim.md) | Enterprise SSO: SAML 2.0 + SCIM 2.0 provisioning | SCIM (9a–9c) done; SAML 9d+9e done (login+ACS) | — | SCIM Users/token/Groups; SAML config+metadata+login/ACS |
| [RFC-010](RFC-010-jira-assets-cmdb.md) | Jira Assets / JSM CMDB integration (enrich + reconcile) | Proposed | — | — |
| [RFC-011](RFC-011-validation-engine-dispatch.md) | Validation engine: dispatch (make the "V" executable) | Phase 1 (safe-check) shipped; [**Phase 2**](RFC-011.2-validation-executor-downgrade-loop.md) proposed | — | validate command + dispatcher + producer endpoint + completion hook |
| [RFC-011.2](RFC-011.2-validation-executor-downgrade-loop.md) | Validation executor + confirm-or-downgrade loop (`nuclei` re-verify → finding-state verdict → `downgrade %` metric) | Proposed | — | 2a = api verdict rule + metric; 2b = sdk-go/agent nuclei executor; 2c = ui |
| [RFC-012](RFC-012-real-bas-execution.md) | Real BAS / attack-simulation execution (de-synthesize the "V") | Phase 0–1 shipped | — | honesty (#270); persist runs (#271); real safe-check dispatch (#272) |
| [RFC-013](RFC-013-defectdojo-coexistence.md) | DefectDojo co-existence connector (buy breadth, build brain; phase DD out) | Phases 1–2c shipped | — | converter (#273); live sync (#274); dependency metric (#275); auto-scheduler (#280) |
| [RFC-014](RFC-014-agent-identity.md) | k8s-style agent identity (short-lived, auto-rotating credentials) | Phases 1a–3 shipped; agent auto-renew shipped (sdk-go v0.5.0) | #281 | self-renew (#282); key expiry (#283); rotation overlap (#285/#286); agent auto-renew (sdk-go #45 / agent #35); 4 = scopes TODO |
| [RFC-015](RFC-015-remediation-groups.md) | Remediation groups — fix a whole "solution family" in one action | Phase 1 shipped | — | `remediation_key` derivation + `finding_remediation_keys` side-table + `GET/POST /findings/remediation-groups` (this PR); 2 = UI + verify loop; 3 = campaign unify |
| [RFC-016](RFC-016-mcp-server.md) | Read-only MCP server — AI-native access to CTEM data (learned from OASM) | Phase 1 shipped | #298 (auth) + #299 (MCP) | tenant-scoped `oct_` API-key auth + `POST /api/v1/mcp` JSON-RPC with 9 read tools; 2 = UI connect page; 3 = per-key rate-limit + scopes + resources |
| [RFC-017](RFC-017-ctem-prioritization-surfacing.md) | CTEM prioritization surfacing & loop closure — make the P0–P3 engine the sortable/filterable, explainable organizing principle; close the Attacker-Profile + Business-Service seams; unify the 4 competing scores | Proposed | — | P1 = sort/filter/default P0-first; P2 = explainability + persist reachability; P3 = seam closure; P4 = score rationalisation; P5 = validation-gated closure + assignment sync + cut synthetic |
| [RFC-018](RFC-018-identity-exposure-discovery.md) | Identity exposure discovery from EntraID (MFA / privilege / stale) — the CTEM Discovery identity attack surface as first-class ExposureEvents | Phase 0 shipped (exposure vocabulary); Phase 1 (Graph app-only emitter) needs admin-consented scopes | — | Phase 0 = 3 identity `event_type`s + migration 000210 + tests (this PR); Phase 1 = per-tenant `client_credentials` Graph reader + scheduled controller + projection; Phase 2 = sign-in risk + identity CTEM-ID category + UI |
| [RFC-019](RFC-019-certificate-transparency-discovery.md) | Certificate-Transparency exposure discovery — the first fully-built external-exposure connector: public crt.sh monitoring of tenant domains → `subdomain_discovered` + `certificate_expiring` ExposureEvents (no credentials/consent) | Phase 1 shipped (crt.sh client + parser + per-tenant controller + 2 exposure types) | — | Phase 1 = SSRF-guarded/rate-limited crt.sh poller, no migration (event types pre-exist), tests (this PR); Phase 2 = lookalike/typosquat + asset promotion |

> Status legend: **Proposed** = under review · **Phase N done** = that phase shipped to `develop` · **Implemented** = fully landed.

---

## Thread A — Ticketing / Mobilization (RFC-006)

Outbound ticketing was non-functional (nil client wired in production). The
thread made it work per-tenant, then layers provider abstraction + configurable
mapping on top.

```
RFC-006  Ticketing provider + mapping  (#136 design)
│
├─ Pre-work (shipped)
│   ├─ #134  idempotent create (one ticket per finding+project)
│   └─ #135  secret redaction in ticket descriptions
│
├─ Phase 0  per-tenant client resolver   ── DONE
│   ├─ api #137   internal/app/jira (ClientResolver, ErrNoTicketingIntegration)
│   │             internal/infra/jira/resolver.go  (mirrors SMTP resolver)
│   │             cmd/server/services.go  (wires repos.Integration + Encryptor)
│   └─ ui  #152   ticketing connect dialog collects Atlassian email
│                 (JSON {email,api_token} creds)
│
├─ Phase 1  TicketProvider iface + MappingConfig (defaults=today)   ── TODO
├─ Phase 2  wire configurable mapping into create + inbound webhook ── TODO
├─ Phase 3  outbound status sync via outbox/worker + echo-guard     ── TODO
│           detailed design: RFC-006-phase-3-bidirectional-sync.md
│           (ticket_links table, echo-guard, conflict policy,
│            WorkItem seam → finding now, remediation_task later)
└─ Phase 4  2nd provider (ServiceNow/GitHub) + finding_tickets + UI ── TODO

Code touchpoints:
  internal/app/jira/sync_service.go      — SyncService, resolveClient, mappings
  internal/infra/jira/{client,resolver}.go
  internal/infra/http/handler/jira_webhook_handler.go
```

Open follow-up, now designed in **[RFC-010](RFC-010-jira-assets-cmdb.md)**:
**Jira Assets / JSM CMDB** integration (pull business-context to enrich
prioritization; reconcile/push discovered assets; link CI to tickets). Today
only the core issue API is used — the Assets API is not touched. Note: a Jira
*project* is a ticket routing destination (config), **not** an asset; Jira
**Assets/CMDB objects** are the asset records RFC-010 reconciles.

---

## Thread B — License-aware scan coverage (RFC-007)

Cover a large estate (e.g. 3000 IPs) with a smaller scan license by rolling
batches, storing everything durably in OpenCTEM. Supports **both** Nessus Pro
(unlimited) and Tenable.sc (active-IP, aging) as first-class engines.

```
RFC-007  License-aware scan coverage  (#138 design)
│
├─ Phase 1  .nessus -> CTIS findings adapter + safety   ── IN PROGRESS
│   └─ api #139   internal/infra/scanner/nessus/converter.go
│                 hosts->assets, ReportItems->findings, CVE/CVSS, fingerprint
│                 report shaped so auto-resolve is scoped to the batch only
│
├─ Phase 2  ScanEngine connector (Nessus Pro + Tenable.sc)          ── TODO
│            per-tenant resolver (mirrors Jira), LicensePolicy, TestConnection
├─ Phase 3  coverage scheduler (criticality+staleness rotation,     ── TODO
│            .sc active-IP cap enforcement, reclaim gated on ingest ACK)
└─ Phase 4  observability (freshness, license utilisation) + UI     ── TODO

Reused existing infra (do NOT rebuild):
  pkg/domain/scan         — Scan.TargetsPerJob (batch size), scheduler, retry
  internal/app/ingest     — async pipeline; AutoResolveStaleByAssets is ALREADY
                            scoped by (tool, scanID, assetIDs) → the safety
                            invariant is enforced at service.go
  pkg/domain/asset        — Criticality + LastScannedAt (rotation cursor)
  pkg/domain/integration  — ProviderTenable + AES-encrypted creds
```

**Engine license models** (decides whether the rotate-delete loop is needed):

| Engine | License | Reclaim | Rotation |
|--------|---------|---------|----------|
| Nessus Pro | unlimited IPs | n/a | not needed (batch = perf only) |
| Tenable.sc | active IPs (cap) | explicit removal (immediate) / aging | first-class; scheduler enforces cap |
| *(Tenable.io)* | assets, 90-day count | deletion lag | rotation can't reclaim in time — excluded |

---

## Where things live

```
docs/rfcs/                  RFC design documents (this folder) + this index
  RFC-00N-*.md
internal/app/<cluster>/     application services (jira, ingest, scan, …)
internal/infra/             infra: postgres, http, jira, scanner/nessus, controller
pkg/domain/<X>/             domain entities (asset, scan, integration, vulnerability)
migrations/                 golang-migrate SQL (latest: 000175)
```

Conventions: PRs/merges target `develop` (never `main`). RFCs are reviewed as a
docs PR, then implemented in phased PRs that reference the RFC number.
