# Sensor ↔ platform trust: mutual-distrust gap analysis

> RFC: [RFC-040](../rfcs/RFC-040-platform-sensor-mutual-distrust.md) (design
> and phases). Related: [sensors.md](sensors.md),
> [agent-identity.md](agent-identity.md), [scan-zones.md](scan-zones.md),
> RFC-023, RFC-031, RFC-032, RFC-034, RFC-035, RFC-036, RFC-038.
>
> Verified 2026-10-03 against `openctemio/openctem` `develop` b09dbf69,
> `openctemio/sensor` `main` c97afb1, `openctemio/sdk-go` `main` 411b664 and
> `openctemio/helm-charts` `main` ae8233f. Paths: `api/…` and `web/…` are in
> this repository; `sensor:…`, `sdk:…` and `helm:…` are in the other
> repositories. Line numbers are for those commits.

> **Changes since the snapshot (checked on `develop` 2026-10-04).** The gap
> table below is the 2026-10-03 snapshot, except S3b–S3f, which were updated
> for #889. These RFC-040 P0 PRs have merged since and close or narrow the
> rows named (re-verify a row before relying on its "attack that works
> today"):
>
> - **S3b–S3f** result binding and quarantine (#889, migration `000317`):
>   see the updated rows.
> - **S2e** the ingest worker drops queued reports of revoked or disabled
>   sensors (#882); revoking or disabling a sensor takes back its leased
>   commands (#902).
> - **S4b** length caps on sensor-supplied finding text on every ingest path
>   (#886).
> - **S4e** data-driven links and images encoded, nonce-based CSP (#884);
>   scanner text encoded in tickets and notifications (#887).
> - **P1d** `scan` commands from `POST /api/v1/commands` are owner/admin only
>   and go through scan target resolution (#877).
> - **P3a** signed custom-template manifests; file and self-contained nuclei
>   templates refused (#869).
> - **B3** audit of scope targets, exclusions, tools and scanner templates
>   (#885).
> - **P2a, P5a** platform side of the sensor-local policy (reported state,
>   refusals, the private-target tenant switch) and hardened install snippets
>   (#916). The sensor side (sdk-go#140, sensor#119) is merged but not
>   released: sensor v0.8.0 and older ignore the policy file and the kill
>   switch.

The owner's goal is **mutual distrust**: compromising one side must not be
enough to exploit the other.

- A compromised sensor (or a stolen sensor key) must not be able to attack
  the platform.
- A compromised platform (web, API or database) must not be able to
  weaponize sensors.

This document records, for every control the owner listed, what the code
does today, where, which RFC covers it, and the concrete attack the gap
allows. It is a snapshot: when a control ships, update its row and the
date above.

## Status legend

| Status | Meaning |
|---|---|
| IMPLEMENTED | in the code on the branches above, enforced on the default path |
| PARTIAL | some of the control exists, or it exists but can be bypassed; the row says which part |
| PLANNED | not in the code; designed in the named RFC and phase |
| MISSING | not in the code and not designed before RFC-040 |

## Trust boundaries today

```
 sensor host (customer network)                 platform
 ──────────────────────────────                 ────────────────────────────────────────────
 sensor process ── HTTPS, bearer rda_ key ──►  Caddy gateway (one site, path split only)
   tools (nuclei, httpx, naabu, …)                │  /api/v1/agent/*  /api/v2/sensor/*   ─┐
   stdout logs only                                │  /api/v1/* (users) /api/v1/admin/*  ─┤
   no local scope list                             ▼                                     │
   no signature checks                          ONE api process (cmd/server)  ◄──────────┘
                                                  one router, one middleware chain,
                                                  one sql.DB pool, one DB role,
                                                  APP_ENCRYPTION_KEY, JWT secret,
                                                  in-process ingest workers
                                                  │
                                                  ▼
                                                Postgres (every table)
```

- One server and one router: `api/cmd/server/main.go:329-330`
  (`http.NewServer` + `routes.Register` for users, admins and sensors).
- One listener and one global middleware chain:
  `api/internal/infra/http/server.go:76-100`.
- One database handle and pool, one DSN, no `SET ROLE`:
  `api/internal/infra/postgres/connection.go:20-29`; sensor repositories
  are built from the same `db` (`api/cmd/server/repositories.go:325-326`).
- The gateway routes sensor and API paths to the same upstream:
  `api/deploy/gateway/Caddyfile:107-110, 144-148`.

## 1. Gap table

### 1.1 Sensor → platform

| # | Control | Status | Evidence | RFC | Attack that works today |
|---|---|---|---|---|---|
| S1 | Separate minimal **sensor gateway** (job pull, result submit, heartbeat), split from admin API, UI and DB, deployable in a DMZ | **MISSING** | Same process, router, middleware chain, DB pool and role as the admin API (see "Trust boundaries"). No gateway binary or mode: `api/cmd/` holds only `server` and CLIs; no `SERVER_MODE`/sensor listener setting exists. Caddy splits by path but has one upstream (`Caddyfile:107-110, 144-148`). | RFC-040 §5.1 | Any bug reachable from a sensor route (CTIS/SARIF/recon parsers, decompression, handlers) executes in the process that holds `APP_ENCRYPTION_KEY`, the JWT secret, integration secrets and a DB role that can read and write every table. A sensor key is the only credential needed to reach that parser surface. |
| S2a | Per-sensor identity: mTLS or equivalent proof of possession | **PLANNED** (RFC-032 P1: Ed25519 + RFC 9421; P5: optional mTLS) | Today a bearer `rda_` key per sensor, sent as `Authorization: Bearer` or `X-API-Key` (`api/internal/infra/http/handler/ingest_handler.go:1306-1324`), stored as HMAC with a dedicated pepper (`api/internal/app/sensor/pepper.go:16-56`, `service.go:1684-1688`). No `ed25519`, `Signature-Input` or client-cert code in the api or sdk. | RFC-032 E4, E5 | A key captured once (TLS-inspecting proxy log, `ps` output from `-api-key`, env dump, chat) works from any host until regenerated. |
| S2b | One-time enrollment token | **PLANNED** (RFC-032 P2) | No `ocse_`, enrollment route or bootstrap route in the api; an admin creates the sensor and receives a long-lived key (`api/internal/infra/http/routes/scanning.go:301`). | RFC-032 E1–E3 | The install command carries the long-lived credential itself. |
| S2c | Short-lived credentials | **PARTIAL** | `SENSOR_KEY_TTL` default 90 days applies only to keys a sensor renews (`api/internal/config/config.go:188-194`); admin-created or regenerated keys never expire. Renewal persists in `SENSOR_STATE_DIR` (`sdk:pkg/platform/bootstrap.go:283-313`). | RFC-032 §10.2 | A key on a sensor that never renews is valid forever. |
| S2d | TPM-held keys where available | **PLANNED** (RFC-032 P5) | Not found (no PKCS#11/TPM code in sdk or sensor). | RFC-032 E4, P5 | Root on the host copies the key file or env. |
| S2e | Instant revocation | **IMPLEMENTED**, two gaps | Every request reads the sensor row; revoked is always refused (`api/internal/app/sensor/service.go:1391-1444, 1482-1493`), no cache. Gaps: the async ingest worker rebuilds a synthetic sensor with `Status: Active` (`api/internal/app/ingest/job_processor.go:105-116`), so reports queued before a revoke are still processed; leased commands of a revoked sensor wait for lease expiry before re-queue. | RFC-032 E7; RFC-040 §5.2 | A sensor revoked for misbehaviour still lands the reports it queued just before. |
| S3a | Per-sensor job authorization (sensor A gets only A's jobs) | **IMPLEMENTED**, with self-asserted gates | Poll and claim are scoped by tenant, sensor pin, zone, tool and capability from auth (`api/internal/infra/postgres/command_repository.go:128-146, 183-199, 368-388`); lifecycle calls check ownership (`api/internal/app/command/service.go:336-341`) and fence on lease epoch (`service.go:300-327`, RFC-035 D6). Unpinned commands are claimable by any sensor of the tenant in the zone; the tool and capability gates use what the sensor itself reports when the admin set no limit (`api/pkg/domain/sensor/reported.go:113-142`). | RFC-030, RFC-035 | A stolen key that reports every tool and capability claims the tenant's unpinned jobs (targets, network map). |
| S3b | Results only for job IDs assigned to that sensor | **IMPLEMENTED** in tenant mode `quarantine`; **PARTIAL** in `warn` (#889) | A report is bound when it names an open command assigned to the submitting sensor: v2 `commands/{id}/results/...`, v1 header `X-OpenCTEM-Command-ID` (`api/internal/app/ingest/binding.go`, `ingest_handler.go` `bindRequest`). Another sensor's command, an unknown one, or one finished more than 15 minutes ago is refused (`COMMAND_NOT_FOUND` / `command-not-found`); another tool than the command's is refused. Unsolicited reports are applied (with the unsolicited limits) only from collector and CI-runner roles (`RoleMayPushUnsolicited`). From other roles, per tenant result policy (`GET/PUT /api/v1/sensors/result-policy`): `quarantine` stores the report for review (`422 RESULTS_QUARANTINED` on v1, items counted `quarantined` on v2; approve/reject under `/api/v1/sensors/quarantined-results`), `warn` applies it with the limits plus an audit entry and a metric. Migration `000317` put every existing tenant on `warn`; tenants created later default to `quarantine`. | RFC-023 C-8, RFC-026; RFC-040 §5.3 | In `warn` mode a worker key still lands unsolicited assets and findings (limited: it cannot change existing assets or reopen human-resolved findings). Paths that send no command id (sdk-go v1 fallback, sdk-go before v0.10.0, sensor CI mode) are unsolicited. |
| S3c | Results stay inside the job (targets, tool) | **PARTIAL** (#889) | A bound report changes only the existing assets its command's targets cover (host, parent domain, CIDR, repository path; `binding.go` `alterScope`), and only with the command's tool. An unsolicited report never changes an existing asset (no flags, exposure, classification, ownership, identifiers, name, tags or properties, no reactivation); an active asset only gets its last-seen time. Still open: new assets outside the command's targets are created (follow-up: RFC-036 candidates). | RFC-040 §5.3 | A compromised sensor with an assigned job plants new hosts outside that job's targets. |
| S3d | Auto-resolve / reopen bound to the job | **PARTIAL** (narrowed by #889) | An unsolicited report never reopens a finding a person resolved (any `resolution_method` except `scan_verified`; `api/internal/infra/postgres/finding_human_resolved.go`); auto-resolved findings still reopen. In `quarantine` mode unsolicited reports never auto-resolve. A sensor that declares no tools no longer auto-resolves. Bound reports auto-resolve only on the assets the command covers. Since research 18 F3 (2026-10-04) only a v2 run bound to a command that completed with exit 0 closes default-branch findings (same tool and scan profile, blinding guard); unsolicited reports never close in any mode, nor do uploads or v1 reports. Still open: `coverage_type` and `is_default_branch` are still report fields. | RFC-040 §5.3 | A CI or collector key in a `warn` tenant closes findings by reporting full coverage without them. |
| S3e | Validation evidence bound to an assigned validate job | **PARTIAL** (#889) | With `command_id`: must be this sensor's open validate command for that finding (`api/internal/infra/http/handler/validation_handler.go`). Without it: refused with `403 COMMAND_REQUIRED` unless the tenant's result policy sets `allow_advisory_evidence`. Still open: `simulation_run_id` and `target.asset_id` are taken from the body unchecked. | RFC-023 C-8; RFC-040 §5.3 | A sensor with a validate command attaches evidence that names an unrelated simulation run or asset. |
| S3f | Other sensor writes bound | **PARTIAL** (#889) | Ingest-job status and scan-session reads are limited to the sensor that owns them, and a scan session no sensor registered can no longer be updated by any sensor (#889). Still open: telemetry `correlation_id` unchecked (`runtime_telemetry_handler.go`); credential ingest lets the sensor choose `reactivate_resolved` (`credential_import_handler.go`). | RFC-040 §5.3 (S3e, S3f follow-ups) | Spoofed telemetry correlation inside a tenant. |
| S3g | Tenant from authentication, never the body | **IMPLEMENTED** | `AuthenticateSource` puts `agt.TenantID` in context (`ingest_handler.go:476-512`); v2 the same (`sensor_results_v2_handler.go:61-84`); v2 provenance stamped by the server (`api/internal/app/ingest/v2.go:39-52`); no body tenant is read anywhere. | RFC-026 | — |
| S3h | Sensor credential refused on non-sensor routes (and vice versa) | **IMPLEMENTED** | Tenant routes accept JWT or `oct_` keys only (`api/internal/infra/http/routes/routes.go:1000-1037`, `middleware/apikey_auth.go:129-157, 329-345`, `middleware/unified_auth.go:78-133`); admin routes need the console session (`middleware/admin_auth.go:73`). Sensor auth is mounted only on `/api/v1/agent/*`, `/api/v1/agent/credentials/*`, `/api/v1/validation/evidence` and `/api/v2/sensor/*` (`scanning.go:138`, `exposure.go:166`, `validation.go:38`, `sensor_v2.go:110`). | — | — (but no detection when a sensor key is tried elsewhere, see B4) |
| S4a | Results: schema validation | **PARTIAL** | v2: strict I-JSON pre-pass, unknown fields refused, enums and ids checked (`api/internal/app/ingest/strictjson.go:42-60, 227-354`). v1 CTIS: unknown fields refused, counts only (`ingest_handler.go:642-656`, `validator.go:29-59`). Recon, chunk, scan, evidence, telemetry: lenient decode. No URL validation anywhere. | RFC-026 | Malformed URLs and unexpected values flow into the database from v1. |
| S4b | Results: size limits | **PARTIAL** | Body: v1 ingest 50 MB (`bodylimit.go:13`, `scanning.go:146`), v2 16 MB encoded / 64 MB decoded, ratio 100, depth 64 (`api/pkg/sensorproto/v2/status.go:137-158`); decompression ≤100 MB, ratio ≤200 (`decompress.go:236-243`, the ratio check can be skipped between 1 MB boundaries, `:207-213`, the 100 MB cap holds); counts 100k assets/findings (`types.go:16-25`). **No length caps** on finding title, description, message or remediation. Edge allows 256 MB (`Caddyfile:67-69`). | RFC-026, RFC-023 §10.8 | Megabyte-sized titles and descriptions stored and rendered on every list page. |
| S4c | Results parsed in a sandboxed async worker | **PARTIAL** | v1 sync by default; `INGEST_MODE=async` stores and queues, but a client can force sync (`?sync=true`, `Prefer: respond-sync`, `ingest_handler.go:627-635`); SARIF, recon, scan and chunk are always sync. v2 validates synchronously, then queues (`v2_receiver.go:206-262`). The worker is an in-process controller (`api/internal/infra/controller/ingest_worker.go:99-139`, `cmd/server/workers.go:662`), not a separate or sandboxed process. | RFC-005, RFC-040 §5.4 | A parser crash or memory blow-up takes the whole API down with it. |
| S4d | Results: string sanitisation on ingest | **PARTIAL** | Log fields: CR/LF stripped, 512 chars (`api/internal/app/ingest/log_sanitize.go:21-29`). Asset-name sanitiser applied only to fallback names (`helpers.go:183-220`, `processor_assets.go:1349, 1457-1499`), not to `assets[].name/value` (`:1236-1241`). No control-character, bidi or HTML handling for finding text. | RFC-040 §5.4 | Bidi-override and control characters in titles and hostnames mislead analysts (Trojan-Source style). |
| S4e | Output encoding in the console and exports | **PARTIAL** | Good: no `dangerouslySetInnerHTML`, `innerHTML`, `eval` or `srcdoc` in `web/src`; markdown is rendered only for human sources (`web/src/features/findings/components/detail/overview-tab.tsx:74, 117`; `HUMAN_SOURCES` in `finding-detail.ts:26`, which sensor ingest cannot produce: `api/internal/app/ingest/mappers.go:172-196`), through a custom sanitiser (`web/src/lib/sanitize-markdown.ts:20-160, 281-284`); client and server CSV escape formula prefixes (`web/src/hooks/use-csv-export.ts:20-34`, `api/internal/infra/http/handler/csv_sanitize.go:10-19`); API HTML uses `html/template`; Slack, Teams, Telegram escape. Gaps: scanner remediation references rendered as raw `href={ref}` (`web/src/features/findings/components/detail/remediation-tab.tsx:609`), plus about 15 other raw `href`/`src` from data (e.g. `pentest-details-tab.tsx:203`, `evidence-tab.tsx:771, 777, 794`, `notification-bell.tsx:133`) while `sanitizeExternalUrl` exists (`web/src/lib/utils.ts:81-89`); CSP `script-src 'self' 'unsafe-inline'` and `img-src 'self' data: https:` (`web/next.config.ts:118-173`); the markdown URL check lets `//host` through (`sanitize-markdown.ts:54`); Jira descriptions carry raw finding text as wiki markup (`api/internal/app/jira/sync_service.go:52-70`, `internal/infra/jira/client.go:91, 106`). | RFC-040 §5.4 | A finding reference `data:text/html,…` or a scheme other than http(s) is a clickable link (React 19 neutralises `javascript:`); scanner text injects links and macros into Jira tickets; `<img src=https://attacker>` in human-entered markdown reports who viewed it. |
| S5 | Optional broker / rendezvous (both sides outbound to a DMZ queue) | **MISSING** | Sensors call the API directly; no queue or relay mode. | RFC-040 §5.5 | — (deployment constraint, not an exploit) |

### 1.2 Platform → sensor

| # | Control | Status | Evidence | RFC | Attack that works today |
|---|---|---|---|---|---|
| P1a | Jobs signed (by a separate signing service / HSM, not the API's DB or web tier) | **MISSING** in code; signing **PLANNED** (RFC-023 D9, P5, P6, Phase 3); a separate signer is new in RFC-040 | Commands are raw JSON (`api/pkg/domain/command/entity.go:102`), sent unchanged (`api/internal/infra/http/handler/sensor_control_v2_handler.go:548-570`). No ed25519/DSSE/JWS/TUF code in api, sdk or sensor. The only "signature" is an HMAC over scanner templates keyed with `APP_ENCRYPTION_KEY` (`api/pkg/domain/scannertemplate/signature.go:28-36`, `api/cmd/server/services.go:1438`), never verified (`scanner_template_service.go:359` has no caller) and not sent to sensors (`api/internal/app/scan/trigger.go:562-568`). RFC-038 settings documents have a `Signature` field the store does not verify (`sdk:pkg/core/settings_store.go:43-45`). | RFC-023 D9/P5/P6, RFC-032 T7, RFC-038 S6, RFC-040 §5.6 | Anyone who can write the `commands` table (SQL injection, stolen DB credentials, a restored backup), run code in the API, or present a certificate the sensor trusts decides what every sensor of every tenant scans. |
| P1b | Nonce and timestamp against replay | **PARTIAL** | Platform-supplied `ExpiresAt` is honoured (`sdk:pkg/core/command_poller.go:702`); claims are idempotent server-side. No nonce, no sequence, nothing the sensor can check independently. | RFC-023 P5, RFC-040 §5.6 | A path attacker or DB writer re-issues an old job. |
| P1c | Two-person approval for scope changes | **MISSING** for widening | Creating an exclusion (narrowing) needs a second person (`api/pkg/domain/scope/entity.go:336-355`). Widening is one action: deactivating or deleting an exclusion (`entity.go:390-400`, `api/internal/app/scope/service.go:385-402`) or adding scope targets needs only `scope:write` (`api/internal/infra/http/routes/assets.go:217-249`), which **members** hold (`api/pkg/domain/permission/role_mapping.go:228`). | RFC-040 §5.6 point 5 | A phished member account removes the exclusion protecting a fragile system and schedules a scan against it. |
| P1d | Platform-side scope check before dispatch | **PARTIAL** | Scans resolve targets and drop active exclusions, fail closed (`api/internal/app/scan/targets.go:63-145`), and check direct targets for private addresses at create (`crud.go:224-269`). There is **no positive in-scope check** (`CheckScope`, `scope/service.go:1291`, is called only by `/scope/check`), no RFC-036 ownership gate on the scan path, and `UpdateScan` skips the config validator (`crud.go:677-688`). **`POST /api/v1/commands`** (`routes/scanning.go:49`, `commands:write`, held by members: `role_mapping.go:210`) stores a free-form `scan` payload with arbitrary targets on any tenant sensor, with no scope, exclusion, zone or SSRF check (`api/internal/infra/http/handler/command_handler.go:178-251`, `api/internal/app/command/service.go:64-113`); only inline templates are restricted to admins (`command_handler.go:221-236`). | RFC-036 (ownership gate), RFC-040 §5.6 | A **member** sends a scan command for any address to any sensor of the tenant, bypassing exclusions and zones; on an on-prem sensor with `SENSOR_ALLOW_PRIVATE_TARGETS=1` that includes the internal network. |
| P2a | Sensor-local, read-only policy set by the network owner (CIDR, port, check-type allow-lists) | **PARTIAL** | What exists locally: built-in deny list (loopback, link-local/IMDS, CGNAT, multicast, reserved) and RFC 1918/ULA blocked unless `SENSOR_ALLOW_PRIVATE_TARGETS=1` (`sdk:pkg/core/scan_target.go:115-134, 330-382`); code-scan path confinement `SENSOR_SCAN_ROOTS` (`:225-274`); local tool list `SENSOR_TOOLS` (`sdk:pkg/sensorkit/kit.go:94-97, 488-498`); a second guard in the sensor (`sensor:internal/executor/validation.go:200-267`, `target_security.go:100-241`). **No CIDR, port or check-type allow-list**: private is all-or-nothing. Gaps: targets are resolved before the tool resolves again (DNS rebinding), trivy image references without a registry host skip the check (`sensor:internal/executor/scan_workspace.go:191-196`). | RFC-023 D8 (Phase 3), RFC-034 §6.4, RFC-040 §5.7 | A compromised platform sends a validly formed job for any private range the sensor can route to, once the operator has enabled private targets at all. |
| P2b | Refuse out-of-scope jobs even when validly signed | **PLANNED** (RFC-023 D8 layer 3) | Nothing is signed (P1a) and there is no local scope (P2a). | RFC-023 D8, RFC-040 §5.7 | — (follows from P1a/P2a) |
| P3a | Declarative jobs only, never shell | **IMPLEMENTED** for execution, **PARTIAL** for content | No exec/script command type; unknown types skipped (`sdk:pkg/core/command_poller.go:694`); tools are the locally registered set; `ExtraArgs`, `Env`, `ConfigFile` are never filled from a payload; of `config` only `allow_interactsh` and `exclude` are honoured (`command_poller.go:1087-1103`); dangerous flags denied (`sdk:pkg/core/extra_args.go:19-120`). But: platform-supplied **custom templates** (nuclei, semgrep, betterleaks; base64, ≤50 × 1 MB) are written and run (`command_poller.go:102-182, 1264-1358`), their hash is checked only against a hash from the same payload (`:1304`), and nuclei **drops `-disable-unsigned-templates` for that run** (`sensor:internal/scanners/nuclei/scanner.go:470-473, 595-597`); `allow_interactsh` from the payload turns on out-of-band callbacks (`scanner.go:63-75, 535-544`); the safe-check validator dials any `host:port` the payload names, after the sensor guard (`sensor:internal/executor/validation.go:410-439`); `timeout_seconds` is unbounded (`command_poller.go:1125-1129`). Code-protocol templates stay off (`-code` never passed). | RFC-023 D11, RFC-038, RFC-040 §5.8 | A compromised API or DB (or a tenant admin) ships an unsigned nuclei template that sends arbitrary requests and payloads to in-scope targets: intrusive or destructive checks that bypass the T0/T1 tiers, with callbacks to public OAST servers. |
| P3b | Plugin and binary updates signed by vendor/build keys | **PARTIAL** | No self-update (binaries and tools ship in images). Images cosign keyless-signed and release checksums signed (`sensor:.github/workflows/docker-publish.yml:240-281, 355-362`, `.goreleaser.yaml:62-69`); tool binaries verified by sha256 at build (`sensor:Dockerfile:125-135, 160-165`). Content: nuclei templates checked against a checksum from the same release or an operator pin (`sensor:internal/content/nuclei.go:120-202`) and managed scans pass `-disable-unsigned-templates`; trivy DB by OCI digest; semgrep rules trust-on-first-use (`sensor:internal/content/semgrep.go:88-121`); **the platform can pin an older content version** (`sdk:pkg/core/content.go:113-116`). Sensor image not covered by the platform's SBOM job; `provenance: false`. | RFC-031 (Part A in implementation, Part B Proposed), RFC-023 P7/P8 | A compromised platform pins an old nuclei-templates release or trivy DB to blind detection of recent CVEs. |
| P4 | Scan credentials not stored on the platform; sensor pulls from a local vault; platform sends a reference | **PARTIAL** | No central scan-credential store; credentials for tools come from local config/env (`sensor:main.go:156-164, 1199-1207`); Tenable sensor mode refuses stored credentials (`api/internal/app/scancoverage/tenable_config.go:118-130`); child processes get an allow-listed environment (`sdk:pkg/core/scanner_env.go:29-70`). But: secrets typed into `scanner_config` are stored and sent in clear, only warned and masked (`api/pkg/domain/scan/config_secrets.go:1-10`); **no vault integration** (no Vault/CyberArk code; `sdk:pkg/credentials/store.go` unused); `SealedSecrets` exists but is not consumed (`settings_store.go:52-55`). | RFC-023 D12, RFC-032 E10 (P3), RFC-040 §5.9 | A token typed into a scan config is readable from the `commands` and `scans` tables, backups and by every sensor that claims the job. |
| P5a | Host firewall: egress only to targets and the gateway on 443, no inbound | **MISSING** (guidance/defaults); no inbound **IMPLEMENTED** | The sensor opens no listener (no health/metrics/pprof server; `WebhookCollector` is never started, `sdk:pkg/core/base_collector.go:401-466`). No egress restriction anywhere: install snippets set no `securityContext`, capabilities, read-only root or NetworkPolicy (`api/configs/sensor-templates/{docker,compose,kubernetes,helm}.tmpl`, Kubernetes only `fsGroup`, `kubernetes.tmpl:94-96`); the chart defaults `sensor.securityContext: {}` and `podSecurityContext: {}` (`helm:charts/openctem/values.yaml:1031-1032`) and has no sensor NetworkPolicy (`helm:charts/openctem/templates/networkpolicy.yaml`). Images run as a non-root user (`sensor:Dockerfile:304, 381`). | RFC-034 (forwarder for proxied jobs only), RFC-040 §5.10 | A weaponized sensor reaches every address its host can route to. |
| P5b | Local rate limit and kill switch | **PARTIAL** | Concurrency `SENSOR_MAX_JOBS` / slots (`sensor:main.go:219`, `sdk:pkg/resource/slots.go:10`); nuclei rate from local config (`sensor:internal/scanners/nuclei/scanner.go:26`), validate capped at 20 rps (`validate.go:37`); per-host concurrency comes **from the payload** (`sdk:pkg/core/command_queue.go:220, 282`). Pause/drain are platform-driven (`sdk:pkg/core/doorbell.go:33-39, 395-398`). No local kill switch other than stopping the process or `-enable-commands=false`. | RFC-030 politeness, RFC-040 §5.7/§5.10 | The owner of the sensor host cannot stop a running campaign without killing the sensor; the platform sets per-host politeness. |

### 1.3 Both directions

| # | Control | Status | Evidence | RFC | Attack that works today |
|---|---|---|---|---|---|
| B1 | Minimal immutable OS plus EDR on sensors | **MISSING** (guidance) | Images are slim/distroless-based and non-root (`sensor:Dockerfile:227, 304, 381`); no host-OS or EDR guidance in the docs or snippets. | RFC-040 §5.10 | — (posture) |
| B2 | Sensor logs to an independent SIEM, not to the platform | **MISSING** | Logs go to stdout/stderr only; the SDK audit logger (`sdk:pkg/audit/logger.go`) is not used by the sensor; no syslog/OTLP sink. The platform keeps no sensor logs either (no log route; `api/internal/infra/http/routes/sensor_v2.go:77-110`). | RFC-040 §5.10, §5.11 | After a platform compromise there is no record, outside the platform, of which jobs a sensor was told to run. |
| B3 | Audit every scope or job change | **PARTIAL** | Audited: scans (`api/internal/app/scan/crud.go:173, 778, 807, 837, 861, 885`; the update event has no actor), scan triggers (`trigger.go:132`), HTTP-created commands (`command_handler.go:255, 945, 975`), scan profiles, pipelines, sensors, zones. **Not audited:** scope targets and exclusions (no audit calls in `api/internal/app/scope/service.go` or `handler/scope_handler.go`), tools (actions defined in `api/pkg/domain/audit/value_objects.go:204-207`, never used), scanner templates, commands created by internal dispatch. The hash chain is **unkeyed** SHA-256 (`api/pkg/crypto/audit_chain.go:37-45`) with a rebaseline path (`api/migrations/000244_audit_chain_rebaselines.up.sql`): anyone with DB write can rewrite history consistently. | RFC-023 P12, RFC-040 §5.11 | Scope widening leaves no audit record; a DB-level attacker can rewrite the chain. |
| B4 | Alerts on anomalous scope, off-hours jobs, unusual sensor API use | **MISSING** (except a few signals) | Exists: sensor offline notification (`api/internal/infra/controller/sensor_health.go:43-64`), cloned-identity flag (`api/internal/app/sensor/service.go:936`), key-IP change on the activity timeline, audit-chain break alert (`controller/audit_chain_verify.go:52-74`). No detection for scope widening, off-hours jobs, sensor keys on non-sensor routes, results outside job targets or result-volume anomalies; the ingest quarantine counter exists but nothing increments it (`api/internal/app/ingest/v2_jobs.go:183-185`). | RFC-040 §5.11 | Every attack above proceeds silently. |

## 2. Answers to the specific questions

**Do sensor routes run in the same process and auth stack as the admin
API?** Same process, router, global middleware (recovery, concurrency,
CORS, 10 MB body limit, per-IP rate limit, timeout, logging), DB pool and
role. The authentication middleware is different per group: sensor groups
use `AuthenticateSource` / `SensorResultsV2Handler.Authenticate`; tenant
routes use `APIKeyAuth.OrJWT(UnifiedAuth)`; admin routes the console
session. (S1, S3h.)

**Can a sensor call a non-sensor route with its credential?** No. `rda_`
keys fail the `oct_` prefix check and JWT validation; admin routes need the
console cookie. No route outside the four sensor groups accepts sensor
auth. Nothing records or alerts on a sensor key presented elsewhere. (S3h,
B4.)

**Is result submission bound to a command assigned to that sensor, with the
tenant from auth?** Tenant always from auth (S3g). Command transitions are
bound and fenced (S3a). Results (since #889): bound when they name an open command
assigned to the sensor (v2 path, v1 `X-OpenCTEM-Command-ID`); unsolicited
reports are applied with limits from collector/CI roles, and from other roles
quarantined or (tenant mode `warn`) applied with limits and audited (S3b).
Validation evidence without a command id is refused unless the tenant allows
advisory evidence (S3e). A bound report changes only the existing assets its
command covers; new assets outside the targets are still created (S3c).

**Ingest size limits and schema validation?** Body, decompression, depth
(v2) and count limits exist; per-field length caps do not; v2 is strict,
v1 CTIS rejects unknown fields but validates little, other v1 routes are
lenient (S4a, S4b).

**How scanner fields are rendered?** No raw-HTML sinks; markdown only for
human-sourced findings, sanitised; CSV escaped; but raw `href` from scanner
references and a permissive CSP (S4e).

**Is any job, command or config signed today?** No (P1a).

**What the sensor enforces locally?** Built-in deny list, private ranges
all-or-nothing, code-scan roots, local tool list, dangerous-flag denylist
(currently inert because no payload fills extra args), target syntax checks.
No CIDR/port/check-type allow-list, no signature check, no kill switch
(P2a, P3a, P5b).

**Where do scan credentials live; are they sent in plaintext?** On the
sensor (local config/env) by design; the platform holds none, except
whatever a user types into `scanner_config`, which is stored and sent in
clear (masked for read-only callers) (P4).

**How are the sensor binary and templates updated and verified?** Binary:
image releases, cosign keyless-signed, no self-update. Nuclei templates:
release checksum or operator pin, signature enforcement on managed scans,
but **disabled** for runs with platform-supplied custom templates; the
platform can pin older content (P3b, P3a).

## 3. Top five risks

Ranked by (likelihood × impact) with the effort to exploit today.

| Rank | Gap | Who can exploit | Impact |
|---|---|---|---|
| 1 | **Unbound sensor writes** (S3b, S3c, S3d, S3e; largely closed by #889, see the rows): any sensor key writes assets and findings for any target in its tenant with no job, merges into existing assets (reactivation, compliance and exposure flags), reopens human-resolved findings by fingerprint, attaches advisory evidence to any finding; legacy sensors can auto-resolve | any stolen `rda_` key (bearer, often non-expiring) or any compromised sensor host | integrity of the whole CTEM picture (priorities, SLAs, exposure, attack paths), with no detection |
| 2 | **No authority check between platform and sensor** (P1a, P1d, P2a): unsigned commands, no sensor-local scope, `POST /api/v1/commands` lets a **member** send arbitrary scan targets to any tenant sensor with no scope/exclusion/zone check | a tenant member; anyone with DB write; API RCE; a path attacker trusted by the sensor's CA store | sensors scan what the attacker chooses, including internal ranges on on-prem sensors that allow private targets |
| 3 | **Platform-supplied custom templates run unsigned** (P3a): nuclei signature enforcement is dropped for those runs; the template "signature" is an unverified HMAC keyed with `APP_ENCRYPTION_KEY`; `allow_interactsh` is payload-controlled | a tenant admin; API or DB compromise | arbitrary request crafting against in-scope targets (intrusive/destructive checks past T0/T1), out-of-band exfiltration of responses |
| 4 | **One process, one DB role for sensors and admins** (S1, S4c): sensor-reachable parsers (SARIF, recon, chunk always synchronous) run beside the encryption key, session secrets and full DB access; the ingest worker is in-process and keeps processing reports of revoked sensors | any sensor key, plus a parser bug | platform compromise from the sensor side; platform outage from a pathological report |
| 5 | **Silent widening and rewritable history** (P1c, B3, B4, B2): scope widening is a single member action and is not audited; the audit chain is unkeyed; there are no anomaly alerts; sensors log only to stdout | a phished member; any DB-level attacker | misuse goes unnoticed and cannot be reconstructed afterwards |

Next in line: raw `href` from scanner references and `script-src
'unsafe-inline'` (S4e); Jira wiki-markup injection from finding text (S4e);
platform-pinned content downgrade (P3b); no host-hardening defaults (P5a).

## 4. Where each gap is addressed

| Gap | Addressed by |
|---|---|
| S1, S4c | RFC-040 §5.1 (gateway), §5.4 (worker) |
| S2a–S2d | RFC-032 P1, P2, P5 (accepted) |
| S2e | RFC-040 §5.2 (revocation reaches queued and leased work) |
| S3a–S3f | RFC-040 §5.3 (one binding rule; P0 for the cheap parts) |
| S4a, S4b, S4d, S4e | RFC-040 §5.4 |
| S5 | RFC-040 §5.5 |
| P1a, P1b | RFC-023 D9/P5/P6 as specified in RFC-040 §5.6 (separate signer, DSSE, `seq`, nonce) |
| P1c, P1d | RFC-040 §5.6 point 5 (two-person widening), P0 command-route fix |
| P2a, P2b | RFC-040 §5.7 (local policy file; RFC-023 D8) |
| P3a, P3b | RFC-040 §5.8, RFC-031, RFC-038 |
| P4 | RFC-040 §5.9 (references), RFC-032 E10 (sealed, opt-in) |
| P5a, P5b, B1, B2 | RFC-040 §5.10 |
| B3, B4 | RFC-040 §5.11 |
