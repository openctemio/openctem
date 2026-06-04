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
└─ Phase 4  2nd provider (ServiceNow/GitHub) + finding_tickets + UI ── TODO

Code touchpoints:
  internal/app/jira/sync_service.go      — SyncService, resolveClient, mappings
  internal/infra/jira/{client,resolver}.go
  internal/infra/http/handler/jira_webhook_handler.go
```

Open follow-up not yet an RFC: **Jira Assets / JSM CMDB** integration (pull
business-context to enrich prioritisation; push discovered assets; link CI to
tickets). Today only the core issue API is used — Assets API is not touched.

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
