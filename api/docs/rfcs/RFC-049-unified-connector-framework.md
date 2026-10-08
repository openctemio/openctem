# RFC-049 — Unified connector framework (platform-direct and sensor-relayed)

> Status: **Proposed** (2026-10-04). Only the P0 security fixes (#1068, #1069) are implemented.
> Decision (2026-10-04, final): OpenCTEM talks to external systems
> through **one connector framework**. Each connector runs either **directly
> from the platform** (reachable systems, cloud SaaS) or **via a sensor**
> (on-prem, internal network), chosen **per tenant per connector**, with one
> shared contract.
> Scope: api (contract host, data model, relay, migration of every existing
> integration), a new shared Go module for the connector code, sensor (the
> sensor-side host), web (one Integrations area).
> Builds on and does not repeat:
> [RFC-047](RFC-047-tenable-sc-sensor-connector.md) (the first sensor
> connector: sensor-local credentials, declarative commands, allow-lists),
> [RFC-040](RFC-040-platform-sensor-mutual-distrust.md) (signed jobs,
> sensor-local policy, result binding, hostile results),
> [RFC-034](RFC-034-sensor-network-egress.md) (egress classes and proxies),
> [RFC-033](RFC-033-sensor-manifest.md) (capability advertisement),
> [RFC-006](RFC-006-ticketing-provider-and-mapping.md) (ticketing provider
> abstraction), [RFC-041](RFC-041-api-path-design.md) (the `/hooks` inbound
> plane).
> Security fixes found during this review: #1068 (secrets in notifier
> errors), #1069 (SMTP DNS rebinding and session deadline).

## 1. Answer in short

- **One contract.** A connector is a Go package that declares a descriptor
  (id, operations, config and credential schemas, egress needs, limits) and
  implements a subset of five operations: `test`, `pull`, `push`, `launch`,
  `sync`. It returns typed errors from one taxonomy.
- **Two hosts, same code.** The connector never builds an HTTP client, reads
  a secret store or touches the network on its own. Its **host** hands it a
  guarded HTTP client, a secrets handle, limits, a redacting logger and a
  result sink. The API worker is one host; the sensor is the other. The
  connector code sits in a small leaf module (`openctemio/connectors`) that
  both import, the way both import `ctis` today.
- **Mode per tenant per connector.** Each integration row gains
  `execution_mode` (`platform` | `sensor`), `sensor_id`, `instance` and
  `credential_store`. Every live integration becomes a platform-mode
  instance with no data rewritten.
- **Sensor mode keeps credentials on the sensor.** The platform knows only
  an instance name. Relayed operations are declarative, sensor-pinned
  commands (`connector_sync`, `connector_scan` from RFC-047, plus new
  `connector_test` and `connector_push`) that carry no URL, header or secret,
  are checked by the sensor-local policy, and will be signed when RFC-040
  signed jobs land. Results come back through the normal ingest path.
- **Egress.** Platform-direct always dials through the SSRF guard. The global
  `OPENCTEM_HTTPSEC_ALLOW_PRIVATE` switch, which today opens private ranges
  for every tenant at once, is replaced by a platform-admin, per-tenant,
  expiring allowlist; the recommended path for anything internal is sensor
  mode.
- **Secrets never come back.** Write-only fields, encrypted at rest under the
  `APP_ENCRYPTION_KEY` keyring, a fingerprint instead of a value, errors
  redacted at the host, no tenant labels on metrics.
- **One Integrations area** shows every instance with its mode, health, last
  sync and last error class, built from shared components.

## 2. Inventory: platform-direct integrations today

The API process makes these outbound connections itself. Every
tenant-configurable HTTP client goes through the SSRF guard in
`pkg/httpsec` (resolve once, vet every answer, dial the vetted address);
private ranges are refused unless the operator allows them. Credentials are
encrypted with `APP_ENCRYPTION_KEY` (AES-256-GCM, with key rotation).

| Integration | Direction | Credentials | Tenant resolution |
|---|---|---|---|
| Slack, Microsoft Teams, Telegram, generic webhook | outbound notifications (outbox) | webhook URL or bot token, encrypted | per tenant |
| Splunk HEC | outbound events | HEC token, encrypted | per tenant |
| Email notifications and transactional mail | outbound SMTP | user/password, encrypted; system SMTP from `SMTP_*` | per tenant, else system |
| Jira | outbound tickets, inbound webhook | email + API token, encrypted | per tenant |
| GitHub Issues | outbound tickets | SCM token | per tenant |
| GitHub, GitLab, Bitbucket, Azure DevOps | repository sync, inbound GitHub webhook | token, encrypted | per tenant |
| DefectDojo | finding import | API token, encrypted | per tenant |
| AI triage (OpenAI, Gemini, Claude) | outbound LLM calls | platform key or tenant key, encrypted and redacted | tenant settings |
| Threat intelligence (EPSS, CISA KEV), CTEM-ID feed, certificate transparency | outbound feeds | none | platform-wide |
| Social OAuth, organization SSO (OIDC, SAML), admin IdP | sign-in | client secrets, encrypted | IdP record or environment |
| Tenant S3 storage | object storage | keys, encrypted | tenant settings |
| Template sources (HTTP, git, S3) | content fetch | secret store | per tenant |
| Automation `http_request` action | outbound HTTP | per-action headers | automation tenant |
| DNS (EASM, domain verification) | DNS queries | none | per tenant |

### 2.3 What is common, what is not

Common: every tenant-configurable HTTP connector already uses the guarded
dialer, and credentials are encrypted in one column. Not common: ten clients
each make their own choices about body caps, retries, redirect policy, error
text and tenant lookup; there is no health model beyond `status`, no cursor
model beyond Tenable's, no audit, no typed error, and no way to run any of
them anywhere but the API process.

## 3. Inventory: the sensor side today

| Piece | State | Evidence |
|---|---|---|
| Tenable.sc connector | Merged on sensor `main`; the platform side is on open PRs #1015 / #1039 behind `TenableConnectorEnabled = false` | sensor `internal/connector/tenablesc/{client,config,sync,scan,mapping}.go` |
| Its client | TLS ≥ 1.2, `ca_file` replaces system roots, SPKI pins (constant-time); own dialer: resolve, refuse if any answer is blocked by `IsIPBlockedWith(ip, allowPrivate=true, allowLoopback=false)`, dial the checked IP; redirects refused; ≤ 5 attempts with full jitter, only network errors and 429/502/503/504, `Retry-After` ≤ 60 s; token bucket; body caps with `ErrResponseTooLarge` (never a truncated parse); numeric-only path ids | `client.go:49-369` |
| Its config | `/etc/openctem/connectors/tenable-sc.yaml`, `KnownFields`, exact `apiVersion`, https only, secrets from `*_file` (regular, not world-writable, capped), `Secret` type redacts on every formatter, per-instance allow-list (`operations`, repositories, policies, zones, limits) | `config.go` |
| Abstraction | **None generic.** Each command type is a plain `core.CommandExecutor`; payload types live in the sensor. sdk-go's older `core.Connector` / `core.ConnectorConfig` (plaintext `APIKey`/`Token` fields) are unused by it. | `sync.go:46-127`; sdk-go `pkg/core/interfaces.go:618-648` |
| Capability advertisement | The sensor registers tool `tenable_sc` (`kind: collector`) **without per-operation capabilities**; the platform checks only the tool name (`SensorRunsConnector`, #1039 `app/tenablesc/service.go:357`), not the RFC-047 §10 `connector_sync`/`connector_scan` capabilities | sensor `main.go:1112` |
| Command types | `connector_sync`, `connector_scan` (RFC-047 branches, migration 000496). No `connector_test`, no push type. | `pkg/domain/command/entity.go:74,77` (#1039) |
| Signed jobs | **Proposed only** (RFC-040 §5.6, phase P1). DSSE + Ed25519 exists only for custom templates (sdk-go `pkg/core/template_signing.go`). | — |
| Sensor-local policy | P0 subset merged in sdk-go/sensor, unreleased: `targets`, `ports`, `tools.allow`, `checks.allow` (by command type), `rate`, kill switch, `CheckDial` hook | sdk-go `pkg/core/local_policy.go`, `local_policy_enforce.go` |
| Egress | RFC-034 Phase 0 (`SENSOR_{CONTROL,CONTENT,SCAN}_PROXY`, proxy-aware client) shipped; the Tenable client sets no `Proxy`, so it ignores them | sdk-go `pkg/httpsec/proxy.go` |
| Logging | Connector errors never include keys; `Logf` exists but `main.go` never wires it, so connector progress is not logged | `sync.go:69` |

RFC-047 is therefore the pattern this RFC generalises: sensor owns reach and
keys, platform owns intent, declarative commands, results through ingest.
What it lacks for reuse is a contract other connectors can implement and a
host the platform can run the same code in.

## 4. Security requirements for the direct connections

Every outbound connection was reviewed against the code for a multi-tenant
deployment. Two defects were fixed at once (F-1, F-3); the remaining items are
requirements the connector host enforces, each referenced by its id in the
sections below.

| # | Requirement | Where |
|---|---|---|
| F-1 | Credentials never appear in error text, status messages, outbox errors or logs (URL-bearing errors are redacted). | **Fixed: #1068** |
| F-2 | Upstream response bodies are never echoed back to the tenant. | Notifiers fixed in #1068; the rest move to the host redactor (§5.6, phase 1) |
| F-3 | SMTP dials the validated address (no second resolution) and every session has a deadline. | **Fixed: #1069** |
| F-4 | Private-range egress is granted per tenant, not process-wide. | Design §9.2 |
| F-5 | TLS verification cannot be disabled by a tenant; a per-instance CA bundle replaces it. | Phase 0 follow-up (§8.3) |
| F-6 | A failed delivery is recorded as failed and retried or dead-lettered. | Phase 0 follow-up PR |
| F-7 | Per-tenant transactional SMTP reads the keys the writer stores and the encrypted credential; secrets never go into metadata. | Phase 0 follow-up |
| F-8 | A credential decrypt failure fails closed in production. | Host, `class=invalid_config` (phase 1) |
| F-9 | Inbound webhooks are routed by instance, carry a per-instance secret and have replay protection. | Design §10.5 |
| F-10 | Pagination links are followed only on the same origin. | Host |
| F-11 | git over ssh dials through the guarded dialer. | Host |
| F-12 | Every response read is bounded. | **Fixed for today's clients:** `httpsec.ReadLimited` / `DecodeJSON` / `NewLimitedReader` (oversize is an error), security-lint Rule 8; the host enforces descriptor `max_response_bytes` |
| F-13 | Instances are loaded only by tenant and id in the query. | Host loads instances only via `GetByTenantAndID` |
| F-14 | Integration create, update, delete, test and credential changes are audited. | §10.2 |
| F-15 | Every integration surface sits behind its module gate (a feature flag, not a boundary). | Phase 4 |
| F-16 | The test rate limit is shared across replicas. | Redis limiter (§10.3) |
| F-17 | Blocked URLs are logged as scheme and host only. | Host |
| F-18 | No integration surface is exposed without a working delivery path (outbound tenant webhooks). | Build on the framework (`push`) or hide (half-built features are hidden) |

Not vulnerable (checked): cross-tenant credential resolution (every resolver
filters by the principal's tenant); notifier `AllowLoopback` is only set by
tests; the workflow dialer only dials vetted IPs; social OAuth hosts are
fixed; the Okta org host is pinned to Okta domains; LLM hosts are fixed and
BYOK keys are redacted; S3 tenant endpoints are validated and dialed through
the guard.

## 5. The connector contract

One contract, written once, implemented by every connector, hosted by two
runtimes. The contract is Go, in a small leaf module (§6.1); this section is
its specification.

### 5.1 Identity and descriptor

Every connector publishes a static descriptor. The platform reads it from the
code it links (platform mode) and from the sensor manifest (sensor mode,
RFC-033 `tools[]` with `kind: connector`).

| Field | Meaning |
|---|---|
| `id` | Stable provider key, the existing `integrations.provider` value (`jira`, `slack`, `email`, `splunk`, `github`, `tenable_sc`, …). Never renamed. |
| `version` | Semver of the implementation. The platform refuses a sensor whose connector major differs from the one it speaks. |
| `category` | The existing `integrations.category` (`notification`, `ticketing`, `scm`, `security`, `cloud`, `custom`). |
| `operations` | The subset of §5.4 the connector implements. |
| `modes` | `platform`, `sensor`, or both (§7.1 gives the matrix). |
| `config_schema` | JSON Schema of the non-secret configuration (base URL, project key, channel, index, …). Rendered by the UI, validated by the API **and** by the host before every run. |
| `credential_schema` | JSON Schema of the secret fields, every one `writeOnly: true`. Never rendered with a value. |
| `egress` | What the connector needs to reach: `fixed` hosts (e.g. `api.telegram.org`, `slack.com`), or `configured` (the base URL in config). Drives the egress check (§9). |
| `limits` | Defaults for rate (requests/s), page size, max response bytes, max run seconds. A host may lower, never raise. |

### 5.2 Instance

An **instance** is one configured connection of one tenant: the existing
`integrations` row plus four new columns (§8.1):

```
integration (tenant_id, id, provider, name, config, metadata, status, …)
  + execution_mode   platform | sensor
  + sensor_id        NULL in platform mode; the pinned sensor in sensor mode
  + instance         NULL in platform mode; the sensor-local instance name
  + credential_store platform | sensor
```

The tenant comes only from the authenticated principal. Every lookup is
`WHERE tenant_id = $1 AND id = $2`; a sensor-mode instance is additionally
bound to a sensor of the same tenant (never a platform sensor, as RFC-047
already enforces for Tenable).

### 5.3 Credential reference

A connector never sees a credential store. It receives a `Secrets` handle from
its host and asks for fields by name:

```go
type Secrets interface {
    // Get returns the named secret field. The value is a Secret, whose
    // String/GoString/MarshalText/MarshalJSON all redact.
    Get(ctx context.Context, field string) (Secret, error)
}
```

| Store | Where the value lives | Who can read it |
|---|---|---|
| `platform` | `integrations.credentials_encrypted`, AES-256-GCM under the `APP_ENCRYPTION_KEY` keyring (with previous keys for rotation). | The API host, at run time only. |
| `sensor` | The sensor-local connector file or secret files (RFC-047 §6.1 pattern: `*_file`, not world-writable, size-capped). | The sensor host only. **The value never transits to the platform**, in any direction, at any time. |

The credential reference is the pair (`credential_store`, instance). In
sensor mode the platform stores no secret column at all; switching a
connector from platform to sensor mode **deletes** the platform-held secret
in the same transaction (§8.3).

### 5.4 Operations

| Operation | Direction | Shape | Result |
|---|---|---|---|
| `test` | out | No arguments. Authenticates and performs one cheap read (`/myself`, `auth.test`, `getMe`, EHLO+AUTH, HEC health). Never sends a user-visible message unless the connector has no read-only probe (then it says so in its descriptor). | `Health{ok, class, detail, upstream_version, checked_at}` |
| `pull` | in | Cursor in, records out (assets, findings, issues, repositories). | Records go through the **normal ingest path** (CTIS, bound to the command in sensor mode); the cursor comes back as an opaque string. |
| `push` | out | One item (notification, ticket create/update/transition/comment, SIEM event) with an idempotency key. | `PushResult{external_ref, external_url}` |
| `launch` | out | A declarative job on gated targets (Tenable.sc scan, future DefectDojo re-import). | Like `pull` for its results. |
| `sync` | both | Composite: `pull` then reconcile (SCM repository import, Jira status sync). | Counts + cursor. |

A connector implements only what its descriptor lists. The platform asks
for an operation only if the descriptor lists it **and** (in sensor mode) the
sensor advertised it for that instance (§7.3).

### 5.5 Status, health and cursor

| Field | Stored on | Written by |
|---|---|---|
| `status` (`pending, connected, error, disabled, expired`) | `integrations.status` (exists) | The host after `test`/`pull`/`push`. |
| `last_error_class`, `last_error_detail` | new columns; `status_message` stays for back-compat | Redacted (§5.6); never a raw error string. |
| `last_test_at`, `last_sync_at`, `next_sync_at` | exist / new | Host. |
| `cursor` | `integrations.metadata.<provider>.cursor` (RFC-047 pattern) | Advanced **only** after the command completed and every report it filed committed in ingest (RFC-047 §7.5 rule, generalised). |
| `stats` | `integrations.stats` (exists) | Host. |

### 5.6 Error taxonomy

Every error a connector returns is a `connector.Error{Class, Retryable,
RetryAfter, Detail}`. `Detail` is produced by the host's redactor: URL reduced
to scheme and host, known secret values scrubbed, any echoed upstream body
capped at 256 bytes (the helper #1068 introduces for notifiers, promoted to the
shared module). Raw `error` strings never reach `status_message`, the outbox,
`notification_events`, command results or logs.

| Class | Retryable | Typical cause |
|---|---|---|
| `invalid_config` | no | Schema violation, missing field. |
| `auth_failed` | no | 401, SMTP 535, bad bot token. |
| `permission_denied` | no | 403, missing scope. |
| `not_found` | no | Project / channel / repository gone. |
| `blocked_by_policy` | no | SSRF guard, tenant egress allowlist, sensor local policy, connector allow-list. |
| `tls_failed` | no | Untrusted chain, pin mismatch, hostname mismatch. |
| `rate_limited` | yes (honour `Retry-After`, capped 60 s) | 429. |
| `unreachable` | yes | DNS failure, connect timeout, reset. |
| `upstream_error` | yes | 5xx. |
| `response_too_large` | no | Over the descriptor's cap; never a truncated parse. |
| `quota_exceeded` | yes (next window) | Platform per-tenant quota (§10.3). |
| `sensor_unavailable` | yes | Pinned sensor offline, command expired unclaimed. |
| `cancelled` | no | Context cancelled, kill switch. |

The UI shows the class (translated) and the redacted detail; support reads
the class first.

## 6. One implementation, two runtimes

### 6.1 Where the code lives

The API does not import sdk-go (RFC-002 decoupled it; the shared CTIS types
moved to the `ctis` module). The sensor does not get imported by anyone. So
the connector code must sit in a module both may import and that drags in
nothing else:

```
github.com/openctemio/connectors            (new leaf module; stdlib + x/time only)
├── connector/        contract: Descriptor, Operation, Secrets, Error, Health,
│                     Host interface, redactor, conformance test-suite
├── notify/{slack,teams,telegram,webhook,email,splunk}
├── ticket/{jira,github}
├── scm/{github,gitlab,bitbucket,azure}
└── security/{tenablesc,defectdojo}
```

Both the API (platform host) and the sensor (sensor host) import it and pin a
version. Option analysis and the recommendation are in §15 Q1.

### 6.2 What the host provides (and the connector may not do itself)

```go
type Host interface {
    HTTP(egress EgressRequest) (*http.Client, error) // guarded, see §9
    Dialer(egress EgressRequest) (DialContext, error) // non-HTTP (SMTP)
    Secrets() Secrets
    Limits() Limits          // descriptor defaults, lowered by host policy
    Log() Logger             // structured, redacting; no tenant labels on metrics
    Emit() Sink              // records for pull/launch; host ships them to ingest
}
```

A connector package **must not** construct an `http.Client`, a
`net.Dialer`, a `tls.Config` with `InsecureSkipVerify`, or read environment
variables. A lint rule (security-lint Rule 1 extended to the connectors
module, and a `depguard` rule forbidding `net/http.DefaultClient`,
`http.Get`, `net.Dial*` there) enforces it. This is what makes the same code
safe in both places: the guard lives in the host, not in each connector.

| | Platform host (API worker) | Sensor host |
|---|---|---|
| HTTP client | `httpsec.SafeHTTPClient` dialer (resolve once, vet every answer, dial the vetted IP), redirects re-vetted, tenant egress allowlist (§9.2) | sdk-go `httpsec` dialer with `IsIPBlockedWith(ip, allowPrivate=true, allowLoopback=false)` (the RFC-047 client's rule), local-policy `CheckDial`, RFC-034 proxy |
| TLS | System roots; per-instance CA bundle allowed; **no skip-verify** | Per-instance `ca_file` and SPKI pins (RFC-047) |
| Secrets | Decrypt `credentials_encrypted` at run time | Read sensor-local files |
| Limits | Descriptor ∧ platform per-tenant quota | Descriptor ∧ connector file `limits` ∧ local policy `rate` |
| Emit | Ingest service with the instance's tenant | CTIS push bound to the command (`core.WithCommandID`) |
| Trigger | Controller tick / outbox worker / user action | Claimed command |

### 6.3 The platform → sensor relay

Relayed operations are commands, exactly like RFC-047's
`connector_sync`/`connector_scan`, generalised:

| Command type | Operation | Exists |
|---|---|---|
| `connector_sync` | `pull` / `sync` | RFC-047 branch (#1015) |
| `connector_scan` | `launch` | RFC-047 branch (#1039) |
| `connector_test` | `test` | new |
| `connector_push` | `push` | new |

One type per operation, not one type with an `operation` field: the
sensor-local policy allows or refuses by command type (`checks.allow`), and
the platform authorises each type separately (RFC-047 §5.3 reasoning).

Payload (all types):

```json
{
  "connector": "jira",            // descriptor id; must match a tool the sensor advertised
  "instance":  "corp-jira",       // sensor-local instance name, never a URL
  "contract":  1,                 // connector major version
  "idempotency_key": "outbox:…",  // push only
  "args": { … }                   // operation-specific, declarative, schema-validated
}
```

Rules, inherited from RFC-047 and RFC-040 and now applying to every
connector:

1. **No URL, path, header, host, filter expression or credential crosses
   from the platform.** `args` are declarative values (a project key, a
   message body, a severity, a cursor) that the connector validates against
   its schema and against the instance's sensor-local allow-list.
2. The command is pinned to one sensor of the instance's tenant
   (`commands.sensor_id`), with a TTL; an unclaimed command expires to
   `sensor_unavailable`.
3. Payload ≤ 64 KiB, `DisallowUnknownFields`.
4. When RFC-040 §5.6 signed jobs land, `connector_*` commands are signed
   like scans; the sensor's `require_signed_jobs` covers them with no
   connector-specific code.
5. Results: `pull`/`launch` records go through normal sensor ingest bound to
   the command (RFC-040 §5.3 result binding, quarantine policy applies);
   `test`/`push` return only `Health` / `PushResult` / `connector.Error` in
   command result metadata, size-capped, treated as hostile input by the
   platform (length caps, output encoding).
6. The completion metadata never contains a credential, a URL or a raw
   upstream body.

Latency: push via the queue costs one claim cycle. The doorbell (RFC-046 §8)
makes that sub-second when the sensor is connected; when it is not, the
outbox keeps the item and retries until its TTL, then dead-letters it with
`sensor_unavailable`. Notification fan-out to a sensor-mode channel is
therefore at-least-once with the idempotency key passed through to the
upstream (`Idempotency-Key`, Jira issue property, Slack `client_msg_id`).

### 6.4 Results through the normal paths

| Operation | Platform mode | Sensor mode |
|---|---|---|
| `pull` assets/findings | Ingest service, tenant of the instance, source = connector id | CTIS push bound to the command → same ingest service |
| `pull` ticket state (Jira/GitHub status sync) | `ticketing` service | Command result → `ticketing` service (declarative status list) |
| `push` notification | Outbox worker records `notification_events` | Outbox worker creates `connector_push`, records on completion |
| `test` | Updates instance health | Same, from command completion |

## 7. Mode selection and migration

### 7.1 Which connector runs where

| Connector | Platform | Sensor | Notes |
|---|---|---|---|
| Slack, Teams, Telegram | yes | yes | Sensor mode for tenants that forbid the platform from holding the webhook/bot token. |
| Generic webhook | yes | yes | Sensor mode is the answer for internal receivers (today they need the global allow-private switch). |
| Email (SMTP) | yes | yes | On-prem relays. Transactional auth mail stays platform-only (§7.4). |
| Splunk HEC / SIEM out | yes | yes | On-prem Splunk is the common case. |
| Jira | yes (Cloud) | yes (Data Center) | Inbound webhooks are platform-only; sensor mode polls. |
| GitHub / GitLab / Bitbucket / Azure DevOps | yes (SaaS) | yes (GHE, self-managed) | Inbound push webhook platform-only. |
| DefectDojo | yes | yes | |
| Tenable.sc | no | **yes** | Decision D-14: sensor only. |
| Threat-intel feeds (KEV, EPSS, NVD, crt.sh) | yes | no | Platform-global data, not a tenant connector. Same host runtime (guarded client, limits, metrics), no instance row. |
| AI-triage LLM | yes | later (§15 Q6) | A self-hosted LLM behind a sensor is plausible; latency and data-handling need their own decision. |
| OIDC / SAML / Entra IdP, SCIM | yes | **never** | Login cannot depend on a sensor being up; the auth plane stays outside the framework (it already uses `SafeHTTPClient` + `tid` pinning). |
| Tenant S3 storage | yes | no | Storage plane, not a connector. |

### 7.2 Choosing

Per tenant, per instance: the create/edit form has a **Runs from** choice,
*Platform* or *Sensor* (a sensor list filtered to active, tenant-owned sensors
that advertise the connector). Defaults: *Platform* for SaaS-only connectors,
the tenant's last choice otherwise. A platform admin can set a deployment
policy `connectors.platform_direct = allowed | saas_only | disabled`
(`saas_only` = the platform host refuses any instance whose configured host
resolves to a private address even if a tenant allowlist exists).

### 7.3 Capability handshake

The sensor registers each configured connector as a tool with `kind:
connector` and capabilities = the operations its file allows, per instance
(`connector:jira`, `connector:jira:push`, …) in the RFC-033 manifest. This
closes two gaps the RFC-047 implementation has today: the sensor registers
only the tool name (no per-operation capabilities) and the platform checks
only the tool name. The platform refuses to save a sensor-mode instance, or
to enqueue an operation, the sensor did not advertise (409, as RFC-047).

### 7.4 Migrating the live integrations

No live config breaks. Steps, each its own PR:

1. Migration adds `execution_mode DEFAULT 'platform'`, `credential_store
   DEFAULT 'platform'`, `sensor_id NULL`, `instance NULL`, the error-class
   columns. Every existing row is a platform-mode instance with its existing
   encrypted credential; nothing is rewritten. Safe on a populated table
   (defaults, no backfill scan, no long lock).
2. Each provider is ported behind its existing provider key: the old client
   in `internal/infra/notifier|jira|scm` becomes a thin adapter over the
   connector package, with golden tests asserting byte-identical requests.
   Config readers accept the old metadata keys forever (the email
   split-storage formats, Splunk `hec_url`, Telegram `chat_id` legacy in the
   notification extension).
3. Only then does the UI offer *Sensor* mode for that provider.
4. Tenable keeps RFC-047's integration fields (`execution_mode: sensor`,
   `sensor_id`, `instance`); they move from `config` JSON to the columns
   with a read-both window.
5. Transactional auth mail (per-tenant SMTP via `IntegrationSMTPResolver`)
   stays platform-mode and is fixed separately: the resolver reads keys the
   writer never writes (§4, F-7), so it is silently inert today.

### 7.5 Switching mode

Platform → sensor: the tenant picks a sensor and instance name; the API
verifies the sensor advertises the connector, runs `connector_test` through
it, and only on success flips the columns **and deletes
`credentials_encrypted`** in one transaction. Sensor → platform: the tenant
re-enters the secret (it was never on the platform). Both write an audit
event `integration.mode_changed` (severity high).

## 8. Data model

### 8.1 Migration (sketch)

```sql
ALTER TABLE integrations
  ADD COLUMN execution_mode   TEXT NOT NULL DEFAULT 'platform'
      CHECK (execution_mode IN ('platform','sensor')),
  ADD COLUMN credential_store TEXT NOT NULL DEFAULT 'platform'
      CHECK (credential_store IN ('platform','sensor')),
  ADD COLUMN sensor_id UUID NULL REFERENCES sensors(id) ON DELETE SET NULL,
  ADD COLUMN instance  TEXT NULL CHECK (instance ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
  ADD COLUMN last_error_class  TEXT NULL,
  ADD COLUMN last_error_detail TEXT NULL CHECK (length(last_error_detail) <= 1024),
  ADD COLUMN last_test_at TIMESTAMPTZ NULL,
  ADD CONSTRAINT chk_integration_mode CHECK (
     (execution_mode = 'platform' AND sensor_id IS NULL AND instance IS NULL)
  OR (execution_mode = 'sensor'   AND credential_store = 'sensor'
                                  AND coalesce(credentials_encrypted, '') = ''));
```

(The final SQL will split the constraint into `NOT VALID` + `VALIDATE` so it
takes no long lock.) The sensor's tenant is checked in the service and by a
trigger-free composite check in the repository (`sensor.tenant_id =
integration.tenant_id AND NOT is_platform_sensor`).

### 8.2 Command types

`connector_test` and `connector_push` join the `chk_command_type` CHECK
(RFC-047's migration 000496 widened it for sync/scan).

### 8.3 Credential lifecycle

| Stage | Rule |
|---|---|
| Write | Write-only fields. The API encrypts with the current keyring key; the plaintext is never logged, never audited, never echoed. |
| Read back | Never. Responses carry `credential_configured: true`, `credential_updated_at`, and a fingerprint (first 4 hex of SHA-256 of the value) so an operator can tell which key is configured. |
| Rotate (key) | Keyring re-encryption job (exists for `APP_ENCRYPTION_KEY` rotation, previous keys accepted during the window). |
| Rotate (credential) | Edit replaces the value; old value is gone; audit `integration.credential_rotated`. Optional `credential_expires_at` drives an "expiring" status. |
| Scope | One credential per instance. No credential sharing between instances; no platform-global credential for a tenant connector. |
| Delete | Deleting the instance or switching to sensor mode deletes the ciphertext in the same transaction. |
| Sensor mode | Lifecycle is the sensor owner's (file on the sensor host, SIGHUP reload per RFC-047); the platform shows only `credential_store: sensor`. |

## 9. Egress control

### 9.1 Platform-direct

Every platform-mode connector call goes through the host's guarded client:
`ValidateURL` before the first lookup, dial-time vetting (resolve once, vet
every answer, dial the vetted IP; non-HTTP transports use
`ResolveSafeHost` + pinned dial as SMTP now does, #1069), redirects re-vetted
by the same dialer and capped at 3, `Authorization` dropped on cross-host
redirect (Go default), response bodies read through a cap, every timeout set
(dial 10 s, TLS 10 s, headers 15 s, total per descriptor).

### 9.2 Private addresses: a per-tenant allowlist instead of a global switch

Today `OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1` opens RFC1918/ULA for **every
tenant and every tenant-supplied URL** in the process (webhooks, SMTP,
Jira, SCM, LLM, template git, S3). In a multi-tenant deployment that lets
any tenant admin reach the platform's own private network (databases,
Redis, the sensor gateway, other tenants' services on the same VPC).

Replacement:

- The global switch stays only for single-tenant on-prem installs and logs a
  startup warning when more than one tenant exists.
- A **platform admin** (not a tenant admin) may grant a tenant an egress
  allowlist entry: `(tenant_id, connector id or *, CIDR or host, port set,
  reason, expires_at, granted_by)`. The guard admits a private answer only if
  it matches an entry for that tenant and connector. Hard-blocked ranges
  (loopback, link-local/IMDS, CGNAT, multicast) are never allowlistable.
- The recommended path for anything internal is **sensor mode**: the
  traffic then originates inside the customer's network, under the
  customer's sensor-local policy, and never from the platform's network.

Why the allowlist is still risky: it makes the API host a pivot into the
allowlisted range; a rebinding name can only land inside the allowlisted
range (the dialer still pins), but anything listening there is reachable
with the tenant's request body. Hence platform-admin-only, expiring,
audited, and port-restricted.

### 9.3 Proxy

The platform host may send connector egress through an operator proxy
(`CONNECTOR_EGRESS_PROXY`). A plain forward proxy defeats dial-time vetting
(the proxy resolves the name), so the host vets first and then issues
`CONNECT <vetted-ip>:<port>` with the original Host/SNI, or requires the
proxy to enforce the same blocklist. Sensor mode uses RFC-034: a new traffic
class `connector` (defaulting to the `control` proxy setting) plus the
local-policy `CheckDial` hook; the RFC-047 Tenable client, which today sets
no `Proxy`, adopts it.

### 9.4 Sensor-relayed

The sensor host enforces, in order: local policy (`checks.allow` for the
command type, kill switch, rate), the connector file's per-instance
allow-list (operations, projects/channels/repositories), its own dialer rule
(private allowed, loopback and link-local never), TLS pins.

## 10. Operations

### 10.1 Observability

Metrics (no tenant, integration or sensor id labels, per #1038):
`connector_operations_total{connector,mode,operation,class}`,
`connector_operation_seconds{connector,mode,operation}`,
`connector_relay_queue_seconds{connector,operation}`,
`connector_bytes_received_total{connector,mode}`. Per-tenant visibility
comes from the instance row and the Activity tab (§11), not from metrics.
Logs carry `integration_id`, `connector`, `mode`, `operation`, `class`; never
secrets, URLs beyond scheme+host, or bodies.

### 10.2 Audit

`integration.created|updated|deleted|enabled|disabled`,
`integration.credential_rotated`, `integration.mode_changed`,
`integration.tested` (result class), `integration.sync_completed|failed`
(counts), `integration.egress_allowlist_granted|revoked` (platform admin).
Push deliveries are recorded in `notification_events` / ticket links, not in
the audit log.

### 10.3 Rate limits and quotas

- Upstream courtesy: descriptor rate (token bucket per instance), honoured
  by both hosts; `Retry-After` honoured, capped at 60 s.
- Platform fairness: per-tenant quotas on platform workers (concurrent pulls,
  pushes per minute, test calls per minute) so one tenant's connector cannot
  starve the outbox or the controller. Replaces today's in-memory,
  per-replica, never-pruned `testRateLimitMap` with the Redis limiter.
- Sensor mode: the sensor's local policy `rate` and the connector file
  `limits`.

### 10.4 Retries and idempotency

Retry only retryable classes, full-jitter exponential backoff (1 s → 30 s,
≤ 5 attempts in one run; the outbox's own backoff across runs). Every push
carries the outbox entry id as idempotency key, passed upstream where the API
supports it and used for "find before create" otherwise (Jira issue property
`openctem.finding`, GitHub issue search by marker). Pull cursors advance only
on committed ingest.

### 10.5 Inbound webhooks

- Route by instance, not by `?tenant=`: `POST /hooks/{integration_id}`
  (the `/hooks` inbound plane already exists in RFC-041's plane table; the
  old `/api/v1/webhooks/incoming/*` prefix is closed with `/hooks` as its
  successor). The instance gives tenant and secret; nothing else in the
  request is trusted for routing.
- Signature: the provider's native scheme (GitHub `X-Hub-Signature-256`,
  Jira Cloud JWT/secret, GitLab token header) or OpenCTEM's
  `X-OpenCTEM-Signature` over `timestamp.body`, constant-time, one secret per
  instance, rotate with overlap (two valid secrets for 24 h).
- Replay: timestamp window ±5 min where the scheme has one, **plus** a
  delivery-id cache (GitHub `X-GitHub-Delivery`, Jira `X-Atlassian-Webhook-Identifier`)
  in Redis for the window, so a captured delivery cannot be replayed even
  for schemes without a timestamp.
- Drop the platform-wide `JIRA_WEBHOOK_SECRET` fallback once per-instance
  secrets cover every live Jira integration (a shared secret is a
  cross-tenant spoofing key if it is ever handed to a tenant).
- Rate limit per instance; body cap 2 MiB; 2xx on processing errors so the
  sender does not retry-storm, with the failure recorded on the instance.
- Sensor mode has no inbound webhooks: the sensor polls (`pull`) instead.

## 11. UI: one Integrations area

Today the settings area has one page per category
(`web/src/app/(dashboard)/settings/integrations/{notifications,scm,ticketing,siem,scanners}`),
each with its own add/edit dialogs, its own status rendering and its own
secret fields (the email dialog alone builds credentials JSON by hand). The
rule "sync everywhere, extract shared" applies: the framework ships the
shared parts and every page uses them.

**One list.** `Settings → Integrations` lists every instance of the tenant,
filterable by category, with the columns: name, connector (icon + name),
**Runs from** (badge: *Platform* or *Sensor · <sensor name>*), health (status
dot + error class), last test, last sync, and an actions menu (Test, Sync
now, Edit, Disable, Delete). Category pages become saved filters of this
list, so existing links keep working.

**One detail page** (`/settings/integrations/{id}`), tabs:

| Tab | Content |
|---|---|
| Overview | Health card (status, class, redacted detail, last test/sync, upstream version), stats, "Test connection". |
| Configuration | Form rendered from `config_schema` (§5.1). |
| Credentials | Write-only fields from `credential_schema`: shows *Configured · fingerprint · updated <date>*, a *Replace* action, never a value. In sensor mode: "Credentials are held by sensor <name> (instance <instance>); edit them on the sensor." |
| Runs from | Mode choice, sensor picker (only active tenant sensors advertising the connector), the egress summary (fixed hosts or configured host, allowlist entry if any). Switching runs a test first (§7.5). |
| Activity | Deliveries (notification events), syncs, tests and audit events for this instance. |

**Shared components** (in `web/src/features/integrations/components/`, used
by every page and by the Tenable.sc page of #1063): `ConnectorModeBadge`,
`ConnectorHealth`, `SecretField` (write-only, fingerprint), `SchemaForm`,
`SensorPicker`, `ConnectorActivity`, `TestConnectionButton`. Permissions:
list/detail need `integrations:read`; everything that writes, tests, syncs
or switches mode needs `integrations:manage`; the egress allowlist lives in
the platform admin console only.

## 12. Threat model

**Assets.** Tenant connector credentials; tenant data leaving the platform
(finding titles in notifications and tickets); data coming in (assets,
findings, ticket states); the platform's own network and cloud metadata;
the sensor host and the customer network behind it; the integrity of the
command channel.

**Actors.** A malicious or careless tenant admin; a low-privilege tenant
member; a compromised or hostile external system (Jira, Splunk, a webhook
receiver, Tenable.sc); a network attacker on the path; a compromised
platform (RFC-040's premise); a compromised or stolen sensor; another tenant.

| # | Abuse case | Control |
|---|---|---|
| T1 | Tenant admin points a platform-mode connector at `169.254.169.254`, `localhost` or the platform's private network, directly or via DNS rebinding or redirect. | Host-provided guarded dialer only (resolve once, vet, dial the vetted IP; redirects re-vetted); connectors cannot build clients (lint); hard-blocked ranges never allowlistable; private ranges only via platform-admin per-tenant allowlist (§9.2). |
| T2 | Upstream response used as a read channel (echoed into status). | Host redactor: 256-byte capped, scrubbed detail; typed class (§5.6). |
| T3 | Credential disclosure to a low-privilege member, in logs, in errors, in API responses. | Write-only fields, fingerprint only; redactor on every error; no secrets in metrics/logs (#1068 pattern generalised). |
| T4 | Cross-tenant: tenant A's operation runs with tenant B's credential or ingests into B. | Instances loaded only by `(tenant_id, id)`; ingest tenant from the instance (platform) or from the sensor's key (sensor), never from payload; sensor must belong to the instance's tenant and not be a platform sensor. |
| T5 | Compromised platform uses sensor mode to make the sensor reach arbitrary internal hosts or exfiltrate sensor-held keys. | Payload carries no URL/host/header/secret; sensor-local per-instance allow-list and local policy decide; credentials never leave the sensor; signed jobs when RFC-040 P1 lands; kill switch. |
| T6 | Hostile external system returns huge, malformed or injection-laden data. | Descriptor caps (never truncated parse), schema-validated mapping, result binding + quarantine (RFC-040 §5.3), output encoding in UI/notifications. |
| T7 | Forged or replayed inbound webhook. | Per-instance secret, native signature scheme, timestamp window and delivery-id cache, routing by instance id, rate limit (§10.5). |
| T8 | Network attacker reads credentials in transit. | TLS verification always on; no tenant skip-verify (F-5); per-instance CA bundle or pins instead. |
| T9 | Noisy neighbour: one tenant's connector exhausts workers or upstream quotas. | Per-tenant quotas on platform workers, per-instance token bucket (§10.3). |
| T10 | Mode switch leaves a stale platform-held secret. | Switch to sensor deletes the ciphertext in the same transaction (§7.5). |
| T11 | Key mismatch silently sends ciphertext/plaintext upstream. | Host fails closed on decrypt failure in production (F-8). |
| T12 | Stolen sensor replays old commands. | Command TTL + lease epoch now; signed jobs with nonce/seq later (RFC-040). |

**Authorization.** All instance routes stay under `ModuleIntegrations` +
`integrations:read|manage`; mode switching and credential replacement are
`integrations:manage` and audited at high severity; the egress allowlist is
platform-admin only; relayed commands are created only by the platform's
own services for a tenant's instance, never by a request that names a sensor
directly.

## 13. Phased plan (PR-sized)

| Phase | PRs | Notes |
|---|---|---|
| **P0 security (now)** | #1068 notifier error redaction; #1069 SMTP pinned dial + session deadline | Merged by the queue when green. |
| **P0 follow-ups** | (a) outbox honours `SendResult.Success` (F-6); (b) per-tenant SMTP resolver reads the stored keys + encrypted credential (F-7); (c) remove tenant `skip_verify` (F-5); (d) GitHub webhook delivery-id replay cache (F-9) | One PR each, no schema change. |
| **P1 contract** | (1) new module `openctemio/connectors`: `connector` package (descriptor, operations, `Secrets`, `Error` taxonomy, redactor, `Host` interface) + conformance suite; (2) lint: no client construction in connector packages, Rule 1 extended to raw dials | No behaviour change. |
| **P2 platform host + data model** | (1) migration (680–689 band at the time): mode columns, error-class columns, `last_test_at`; (2) API host: guarded HTTP/dialer, decrypting `Secrets`, limits, Redis quotas, metrics, audit `integration.*`; instances loaded by `(tenant_id, id)` only | Every row = platform mode. |
| **P3 port notifications** | One PR per provider family: webhook+Slack+Teams; Telegram; Splunk; email. Old `notifier` types become adapters; golden request tests. | Byte-identical requests. |
| **P4 relay** | (1) `connector_test` + `connector_push` command types; (2) sensor host in the sensor (secrets from files, sdk-go guard, `connector` proxy class, local policy); (3) per-operation capabilities in the manifest and the platform check (closes the RFC-047 gap); (4) outbox → `connector_push` path with idempotency; (5) web: *Runs from* + shared components | First dual-mode connectors: webhook, SMTP, Splunk. |
| **P5 ticketing & SCM** | Jira (Cloud platform / DC sensor), GitHub Issues, SCM providers, DefectDojo; `/hooks/{integration_id}` inbound routes; drop the global Jira secret after migration | |
| **P6 Tenable onto the contract** | Move RFC-047 payload types into `connectors/security/tenablesc`; integration fields → columns (read-both window) | Sensor-only stays. |
| **P7 egress** | Per-tenant private allowlist (platform admin console), startup warning on the global switch in multi-tenant deployments, `CONNECTOR_EGRESS_PROXY` with vet-then-CONNECT | |
| **P8 signed connector jobs** | When RFC-040 P1 ships, `connector_*` commands signed like scans | No connector code change. |

## 14. Alternatives considered

| Alternative | Why not |
|---|---|
| Keep the API clients and add a separate sensor implementation per connector. | Two implementations drift (the Jira mapping alone has three formats); every fix twice; exactly what this framework exists to end. |
| Put the connectors in sdk-go. | The API deliberately does not import sdk-go (RFC-002); sdk-go's scope is the sensor runtime and safety; connectors would pull sensor concerns into the API build. |
| Put the connectors in the api module and let the sensor import it. | The sensor would import the whole API module (DB, HTTP stack, migrations). |
| One generic `connector` command type with an `operation` field. | The sensor-local policy allows by command type; RFC-047 §5.3 rejected it for the same reason. |
| Send platform-held credentials to the sensor at claim time (HPKE-sealed, RFC-032 §6.6). | Credentials would transit the platform; breaks "credentials never transit in sensor mode"; RFC-047 rejected it for Tenable. |
| Sensor opens an inbound tunnel so the platform can call internal systems directly. | Inverts the trust model (RFC-040), adds an inbound attack surface into customer networks, and makes the platform the dialer again. |
| Keep the global allow-private switch. | Opens the platform's network to every tenant (F-4). |

## 15. Open decisions

**Q1. Where does the shared connector code live?**
(a) a new leaf module/repo `openctemio/connectors` (stdlib + `x/time` only), imported by api and sensor, released with the train;
(b) sdk-go `pkg/connectors` (reverses RFC-002 for the API);
(c) a nested module in the monorepo (`connectors/`), tagged `connectors/vX`.
**Recommend (a)**: same pattern as `ctis`, no dependency inversion, its own CI with the conformance suite. (c) is acceptable if fewer repositories are preferred.

**Q2. May a tenant run a connector platform-direct against a private address?**
(a) never: private targets require sensor mode;
(b) only via a platform-admin, per-tenant, expiring allowlist (§9.2);
(c) keep the process-wide switch.
**Recommend (b)**, with (a) as the default for SaaS deployments (`connectors.platform_direct = saas_only`).

**Q3. Which connectors get sensor mode first?**
(a) generic webhook + SMTP + Splunk (internal receivers, today blocked or forced onto the global switch);
(b) Jira Data Center + self-managed GitLab/GHE;
(c) all at once.
**Recommend (a)** in P4, (b) in P5.

**Q4. Notification delivery through a sensor: what guarantee?**
(a) at-least-once with the outbox TTL and an upstream idempotency key, dead-letter as `sensor_unavailable`;
(b) best effort, drop when the sensor is offline.
**Recommend (a).**

**Q5. Tenant control over TLS for connectors.**
(a) no skip-verify anywhere; a per-instance CA bundle (PEM) and optional SPKI pin;
(b) keep `skip_verify` for SMTP only.
**Recommend (a)**; it also fixes F-5.

**Q6. AI-triage LLM through a sensor (self-hosted model inside the customer network)?**
(a) not now: platform-direct only, fixed providers and BYOK;
(b) allow an OpenAI-compatible endpoint via sensor mode in P5.
**Recommend (a)** until there is a customer request; it needs its own data-handling review.

**Q7. Outbound tenant webhooks (CRUD exists, no delivery: F-18).**
(a) hide them now (half-built features are hidden) and rebuild as a `push` connector in P3;
(b) leave as is.
**Recommend (a).**

**Q8. Per-tenant transactional mail (invitations, resets) through the tenant's SMTP integration.**
(a) keep it, fixed in P0 follow-up (F-7), platform mode only;
(b) remove it: transactional mail always uses the system SMTP.
**Recommend (a)** for on-prem tenants that require their own relay; the login plane never goes through a sensor.
