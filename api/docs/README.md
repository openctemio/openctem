# Documentation

## Quick Links

- [Getting Started](getting-started.md) - Start here!
- [**User Guide**](user-guide/README.md) — end-user product guide (analysts/operators): the CTEM loop, sign-in, scoping → discovery → prioritization → validation → mobilization, insights, settings
- [Architecture Overview](architecture/overview.md)
- [Development Setup](development/setup.md)

---

## Contents

### Getting Started
- [Getting Started Guide](getting-started.md) - Prerequisites, installation, quick start

### Architecture
- [Overview](architecture/overview.md) - Tech stack, system diagram, design principles
- [Clean Architecture](architecture/clean-arch.md) - Layer details & dependencies
- [Project Structure](architecture/project-structure.md) - Complete file structure
- [Notification System](architecture/notification-system.md) - Real-time alerts, providers, async patterns
- [External Attack Surface Management](architecture/easm.md) - EASM pipeline (seeds → passive collectors on the API → attribution with evidence and confidence → active steps on sensors → observations and diffs), what is built vs planned, known limits (RFC-036)
- [Automations](architecture/automations.md) - How automation runs start: one run per subject, idempotency, hourly quotas, execution slots, loop guard, stuck-run reaper, pause on repeated failures
- [Change Detection](architecture/change-detection.md) - What changed in the attack surface: state history views, `asset_discovered` / `scan_completed` triggers, throttled new-internet-facing-asset notification
- [Scan Orchestration](architecture/scan-orchestration.md) - Pipeline execution, agent coordination
- [CTEM Program Metrics](architecture/program-metrics.md) - MTTD for new internet-facing assets, MTTR for validated exposures, owner acceptance rate: exact definitions, tenant scoping, "—" for not measurable, and why time-to-break attack paths is not computed
- [Scoping Overview](architecture/scoping-overview.md) - `GET /scoping/summary` readiness counts (exact definitions, tenant-wide like Program Health) and the cycle attacker-profile list/link/unlink endpoints
- [Scan Coverage (Tenable)](architecture/scan-coverage.md) - License-aware rolling coverage, Nessus Pro + Tenable.sc, .nessus→CTIS converter
- [Sensors](architecture/sensors.md) - Sensor vocabulary (scanner/agent/collector roles), code layout, protocol v2 (RFC-026 results, [RFC-029](rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md) whole surface) and the deprecated protocol v1 legacy package (RFC-023)
- [Sensor ↔ Platform Trust](architecture/sensor-platform-trust.md) - Mutual-distrust gap analysis: every control (gateway split, per-sensor identity, object authorization, hostile results, signed jobs, local policy, credentials by reference, host hardening, audit, detections) with status, file:line evidence and the attack each gap allows today ([RFC-040](rfcs/RFC-040-platform-sensor-mutual-distrust.md))
- [Scan Zones](architecture/scan-zones.md) - Tenant address ranges → zone sensors: narrowest-zone routing and batching at trigger time, the zone claim predicate, run completion over batches, coverage view, UI contract (RFC-023 Phase 1)
- [Sensor Result Binding](architecture/sensor-result-binding.md) - Which sensor reports may change existing assets and findings: bound to an assigned command (v2 path, v1 `X-OpenCTEM-Command-ID`), unsolicited limits, collector/CI roles, tenant mode warn/quarantine, the results quarantine and its review API (RFC-040 group C, Q6 (a))
- [Plans and Limits](architecture/plans-and-limits.md) - Free/Pro/Enterprise limits, console defaults and per-organization overrides, over-limit without removal, the fail-closed check and 403 PLAN_LIMIT
- [Step-up Re-authentication](architecture/step-up-reauth.md) - Sensitive routes need a sign-in or step-up (TOTP, else password) in the same session within 10 minutes: sessions.step_up_at, RequireRecentAuth, STEP_UP_REQUIRED, the protected routes and the threat model
- [Organization Settings](architecture/organization-settings.md) - How tenants.settings is stored and written: one section per write with a compare-and-swap, ETag/If-Match and 409 SETTINGS_CONFLICT, a corrupt section fails closed
- [Audit Hash Chain](architecture/audit-hash-chain.md) - Tamper-evident per-tenant SHA-256 chain over audit_logs: append, verify, the hourly verifier, and rebaselining (when it is allowed, what is archived in the same transaction, how to review overwritten hashes)
- [Shift-Left CI Scanning](architecture/shift-left-ci-scanning.md) - Agent-first SAST/SCA/secrets in CI: structure + dataflow diagrams, branch-aware findings, risk-aware gate, PR decoration (RFC-008)
- [Ticketing Integration (Jira)](architecture/ticketing-integration.md) - Per-tenant client resolver, create/link/webhook, Mobilization
- [Tenable.sc sensor connector](architecture/tenable-sc-connector.md) - RFC-047 pull path: connector_sync commands, sensor-held keys, cursor, source-asserted resolve
- [Tenable — User & Data Flow](architecture/tenable-user-and-data-flow.md) - How operators interact with Tenable on the UI + end-to-end data flow (agent/direct/upload)
- [Data provenance](architecture/data-sources.md) - where assets and findings come from (sensors, integrations, imports)
- [Global Catalog Trust](architecture/global-catalog-trust.md) - Who may write the CVE, component and license catalogs every tenant shares: trusted feeds only, tenant input creates but never changes, tenant views read the tenant's own observation first
- [Asset Schema](architecture/asset-schema.md) - Standard JSON schema for asset ingestion
- [Asset Properties Schema](asset-properties-schema.md) - JSONB properties schema per asset type
- [Database Notes](architecture/database-notes.md) - Important DB implementation details (finding_count, provider detection)
- [SSO Authentication](architecture/sso-authentication.md) - Per-tenant + env-fallback Entra/OIDC design, id_token verification, nOAuth/`xms_edov`, PKCE, verified-domain JIT gate (see also the operator [how-to](how-to/configure-entraid.md))
- [Multi-Tenant EntraID Model](architecture/multi-tenant-entraid-model.md) - "One platform, many tenants — each brings its own EntraID": per-tenant Azure apps, `?org=` login routing, and the `tid`-pin isolation wall (conceptual model)

### Authorization & Access Control
- [Authorization Matrix](architecture/authorization-matrix.md) - **Canonical "how we do authz"**: the layered model (permission / team-role / module-gate / data-scope / RLS), routes-by-auth-type, the settled rules we lock going forward (allow-only, no deny-gate, no expiring grants), the two CI invariants that stop drift, and how-to recipes (add a permission, gate a route, object-level authz)
- [Asset Deletion](architecture/asset-deletion.md) - A delete never destroys findings: refused with 409 while the asset has findings (archive instead), otherwise a soft delete that detaches the asset, frees its name and is purged after 30 days; findings FK is NO ACTION
- [Asset Ownership](architecture/asset-ownership.md) - The one owner model (`asset_owners` RACI): primary user owner and responsible owner definitions, the `owner_ref` email match, the 2026-10 migration from `assets.owner_id`, and why an owner is not an access grant (explicit `asset_access_grants`)
- [Access Control Rules](architecture/access-control-rules.md) - Scope rules + assignment rules (who sees which data, how roles are assigned)
- [User Two-Factor Authentication](architecture/user-two-factor-authentication.md) - TOTP 2FA for organization users (RFC-024): login challenge → `/auth/mfa/verify`, forced enrollment under "Require MFA", token-mint policy gate, recovery codes, immediate session revocation, My account API
- [Permission Real-time Sync](architecture/permission-realtime-sync.md) - Effective-permission cache, per-user version bump, 0-second revocation, 409-on-stale-write
- [Tenant API Keys (`oct_`)](architecture/api-keys.md) - What a key carries, read-only REST access next to MCP, scopes narrowed to what the key's user holds now, refused routes, CSRF, rate limit, audit attribution, and the open write-access decision
- [Authorization Audit (2026-09)](authz-audit.md) - Historical snapshot of the review that produced the standardization (AUTHZ-01..17, endpoint inventory), with a status table of each finding on `develop`; the current model is the authorization matrix

### Architecture Decision Records (ADR)
- [ADR-001: Use Standard net/http](architecture/decisions/001-use-stdlib-http.md)
- [ADR-002: Multi-Protocol API](architecture/decisions/002-multi-protocol.md)
- [ADR-003: Connector Pattern](architecture/decisions/003-connector-pattern.md)

### API
- [API Reference](api/README.md) - Quick reference
- [Endpoints](api/endpoints.md) - REST API details

### How-To (Operator Guides)
- [Configure Jira ticketing](how-to/configure-jira-ticketing.md) - Connect Jira Cloud, severity/status mapping, bidirectional sync, the inbound-HMAC gotcha
- [Configure SCIM provisioning](how-to/configure-scim-provisioning.md) - IdP user provisioning/deprovisioning, tokens, group→role mapping (API-only)
- [Configure SIEM (outbound & inbound)](how-to/configure-siem.md) - Splunk HEC forwarding + SIEM-detection ingest → IOC correlation / auto-reopen
- [Fix a sensor's setup checklist](how-to/fix-sensor-setup-checklist.md) - Read the sensor's Setup & health checks, apply the fix snippet for your install type (env, Compose, Helm), confirm the check passes
- [Enable Restricted Data Scope (fail-closed)](how-to/restrict-data-scope.md) - Scope non-admins to only their assigned assets/findings (Tenable "No Access" default); rollout order + how to enable
- [Configure Microsoft Entra ID (Azure AD) SSO](how-to/configure-entraid.md) - Both Microsoft login paths, Azure app registration, env vars/admin UI, `xms_edov` claim, verified domains, redirect allow-list, troubleshooting (incl. the login-button 404)

### Development
- [**Repositories & how the platform fits together**](development/repositories.md) — **new devs start here**: the six `openctemio` repos (api/ui/agent/sdk-go/ctis/helm-charts), how they talk, where to do what, and cross-repo gotchas
- [Development Setup](development/setup.md) - Full environment setup
- [Coding Style](development/coding-style.md) - Conventions
- [Migrations](development/migrations.md) - Database migrations guide
- [CI/CD](development/ci-cd.md) - GitHub Actions workflows

### Deployment
- [Monitoring and alerting](operations/monitoring.md) - Operator monitoring of the running platform (`deploy/observability`): API metrics, exporters, alert rules routed to Telegram/Slack, what an alert may contain, and a runbook per alert
- [Safe Deploy & Migrations](deployment/safe-deploy-and-migrations.md) - Canonical safe-deploy sequence, expand-contract rules, schema-check semantics, dirty-migration recovery, rollback
- [Least-privilege database roles](deployment/database-roles.md) - The API connects as `openctem_app` (DML only), migrations as `openctem_migrator` (schema owner); the bootstrap script, what the API needs at run time, compose/helm variables, and the upgrade runbook
- [Rotating APP_ENCRYPTION_KEY](deployment/encryption-key-rotation.md) - What the key protects, `cmd/rekey` (dry run, apply, sweep), `APP_ENCRYPTION_KEY_PREVIOUS`, and the zero-downtime runbook
- [Docker](deployment/docker.md) - Docker & Docker Compose (dev/prod)
- [Kubernetes](deployment/kubernetes.md) - K8s manifests

---

## Project at a Glance

| Component | Technology |
|-----------|------------|
| Language | Go 1.26+ |
| HTTP | Standard `net/http` |
| Database | PostgreSQL 17 |
| Cache | Redis 7 |

## Quick Commands

```bash
# Development (Docker with hot reload)
make docker-dev

# Production
make docker-prod

# Local development
make dev

# Run tests
make test
```
