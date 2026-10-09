# RFC-038 — Sensor tool settings: typed schemas from the sensor, forms on the platform, signed config back

> Status: **Proposed** (2026-10-02, #826). §6.12 custom template trust is implemented; the settings schema design (§6.1–§6.10, phases P0–P4) is not built.
> Scope: sdk-go (schema types, registration, delivery and verification) +
> sensor (`openctemio/sensor`: one schema per tool, typed option → flag
> mapping) + api (storage, validation, policy, audit, push) + web (forms).
> Builds on [RFC-032](RFC-032-sensor-enrollment-and-identity.md) (sensor
> Ed25519 keys, the platform's job-signing root pinned at enrollment, HPKE
> sealing), [RFC-033](RFC-033-sensor-manifest.md) (manifest, digest, policy
> echo, `config_version`), [RFC-034](RFC-034-sensor-network-egress.md)
> (egress profiles: the pattern of "reference, never inline secret") and
> [RFC-036](RFC-036-easm.md) (T0/T1/T2 intrusiveness tiers).
> Mutual distrust: [RFC-040](RFC-040-platform-sensor-mutual-distrust.md)
> §5.6 signs settings documents with the same separate signer as jobs and
> amends S6 to a DSSE envelope over the exact bytes (no canonical JSON,
> because re-serialising lets a verifier and an executor read different
> documents); a job names the settings version and digest it
> runs with.
>
> Problem (2026-10-02): tools in the sensor need input options and custom
> config. The SDK should have an interface for the sensor to register those
> customisations; the platform receives them; when adding or editing a sensor
> the admin can customise those parameters in the UI; the sensor receives
> them back, stores them and runs with the right options. The design should
> be the most secure and current option available.

## 1. Answer in short

**Each tool in the sensor declares a typed settings schema. The sensor
registers it in its manifest (by digest, so heartbeats stay slim). The
platform stores it, renders a form from it, validates what the admin
enters against it on the server, applies policy (tier, tenant, zone), audits
the change, and pushes a signed, versioned settings document back. The
sensor checks the signature, validates the document against its own schema,
stores it atomically, applies it to the next job and reports the version it
applied.** Settings are typed values that the tool's adapter maps to
specific flags. They are never free-form command-line text.

| | Today (verified 2026-10-02) | With this RFC |
|---|---|---|
| Where a tool's options are declared | nowhere the platform can read. Tool knobs are sensor env vars (`SENSOR_CONTENT_*`, `TRIVY_*`) or hard-coded in the wrapper | a schema per tool, versioned, in the manifest |
| How an admin changes them | edits the host's env and restarts the container | a form on the sensor's page, generated from the schema |
| What reaches the scanner from the platform | `scanner_config` / scan-profile `options`: free-form `map[string]any`, checked by a key/value **denylist** (`SecurityValidator.ValidateScannerConfig`); the SDK honours only `allow_interactsh` and `exclude` (`command_poller.go`) | only keys the tool declared, with their declared types and bounds, checked on the platform **and** on the sensor (allow-list) |
| `tools.config_schema` / `tenant_tool_configs.config` (migration 000015) | columns exist, written by the tool admin API, never used to validate anything | superseded for sensor tools by the schema the sensor reports (§6.4) |
| Secrets (API tokens for a tool, e.g. a private template repo) | in `scanner_config` in clear; RFC-032 G7 only warns | write-only fields, encrypted at rest, sealed to the sensor's key in transit (§6.8) |
| What the platform knows the sensor runs with | nothing | the applied version and digest per sensor; drift is visible |

## 2. Decisions

| # | Decision |
|---|---|
| S1 | **Schema language:** a constrained subset of JSON Schema 2020-12 (types, `enum`, `const`, numeric/length/item bounds, `pattern`, `default`, `title`, `description`, `deprecated`, `writeOnly`, `additionalProperties: false`), plus `x-octm-*` annotations for what JSON Schema does not say: `x-octm-scope` (`sensor` / `scan`), `x-octm-tier` (minimum tier T0/T1/T2 for a value to be allowed), `x-octm-sensitive`, `x-octm-group`, `x-octm-order`, `x-octm-restart`. One root object per tool, flat or one level of nesting. No `$ref`, no `oneOf/anyOf`, no `patternProperties` (§6.1). |
| S2 | **Schemas live with the tools, in the sensor.** The SDK defines the Go type (`core.SettingsSchema`), the registration hook (`ToolSpec.Settings`), digests, delivery, signature checks and the store. Adding a tool or an option never needs an SDK release (fits sdk-go `docs/STABILITY.md`). |
| S3 | **Registration is part of the RFC-033 manifest:** each `ManifestTool` gains `settings: {schema_version, digest}`; the schema body is sent once (`PUT /api/v2/sensor/tool-schemas`, content-addressed by digest) and fetched on `send_tool_schemas`. Heartbeats never carry schemas. |
| S4 | **Server-side validation is authoritative.** The api validates every write against the stored schema (never trusts the form), then evaluates policy rules (S5), then audits. |
| S5 | **Policy constraints use CEL** (cel-go): non-Turing-complete, cost-bounded, sandboxed. Built-in rules ship as code (tier, sensitive, scope); tenant-authored rules are a later phase. OPA/Rego is rejected as an extra service and language for this size of problem (§9). |
| S6 | **Delivery is a signed document**, `SensorSettings{sensor_id, version, issued_at, expires_at?, tools: {name: {schema_digest, values}}}`, signed with the platform's job-signing key that the sensor pinned at enrollment (RFC-032 T7 / RFC-023 P6). Until that key exists, the document travels on the sensor's authenticated v2 channel (TLS + RFC 9421 signed request) and its digest is echoed in the heartbeat. Monotonic `version` blocks rollback (TUF's idea). |
| S7 | **The sensor validates against its own schema**: unknown keys, wrong types, out-of-range values and a schema digest it does not have are **rejected**, not dropped. It stores the accepted document atomically (temp + fsync + rename, 0600, dir 0700) on the state volume, applies it from the next job (running jobs keep their settings), and reports `{version, digest, status, errors}` back. |
| S8 | **Options map to flags in the adapter, typed.** Each option is a field the adapter turns into specific argv entries with `strconv`/fixed strings (e.g. `rate_limit: 150` → `-rate-limit 150`). There is no "extra args" option. Every built argv still passes `core.ValidateExtraArgs` / `DangerousToolFlags` as a backstop. |
| S9 | **Precedence:** tool default < sensor settings < scan-profile settings < scan settings, and a level may set a key only if its `x-octm-scope` allows that level. The effective value and where it came from are shown in the UI and recorded per job. |
| S10 | **Secrets are write-only.** In the API and UI they are never returned (the UI shows only "set / not set"); at rest they are encrypted with the tenant key (`secretstore.Encryptor`, `APP_ENCRYPTION_KEY`); in transit they are HPKE-sealed to the sensor's X25519 key (RFC-032 E10). Legacy `rda_` sensors cannot receive secret settings. |
| S11 | **Admin-only.** Reading the schemas and effective settings is `sensors:read`; changing sensor-level settings is `sensors:write`, which is owner/admin only (authz audit #2 decisions). Scan-level overrides use the existing scan permissions and only for `scope: scan` keys. Every change is in the hash-chained audit log with a redacted diff. |
| S12 | **Evolution is additive.** New options are new optional keys with defaults. Removing or narrowing an option is a new schema version; the platform migrates stored values or marks them invalid and shows it. Old sensors (no schema) keep working and show no form. |

## 3. Current state (verified 2026-10-02: api `develop` 4d583ab2, sdk-go `main` c82fe0d, sensor `main` 92edff4)

### 3.1 How a scan's options reach a tool

1. The api builds a command; its payload has `config: map[string]any`
   (from the scan's `scanner_config`, or a scan profile's
   `tools_config[tool].options`, `scanprofile.ToolConfig.Options
   map[string]any`).
2. Before saving, `SecurityValidator.ValidateScannerConfig`
   (`api/internal/app/security_validator.go`) refuses known-dangerous keys
   and values (`DANGEROUS_CONFIG_KEY`, `DANGEROUS_CONFIG_VALUE`): a
   denylist.
3. On the sensor, the SDK's command executor
   (`sdk-go/pkg/core/command_poller.go`) copies **two** keys into
   `core.ScanOptions`: `allow_interactsh` (bool) and `exclude` (strings,
   each checked by `validateScanArgValue`). Every other key is ignored.
4. Wrappers take everything else from their own struct fields, set in sensor
   code or from env vars, and `core.ScanOptions.ExtraArgs`, which is now
   guarded by `core.ValidateExtraArgs` in every wrapper (sdk-go#125).

So today an admin cannot set, for example, nuclei's rate limit for one
sensor, and a key typed into a scan profile silently does nothing.

### 3.2 Facts the design depends on

- `core.ToolSpec` (`sdk-go/pkg/core/tool_registry.go`) is where a sensor
  registers a tool (name, kind, version, capabilities, probe, cost). The
  sensorkit builds the manifest from the registry (RFC-033 M9). A settings
  schema belongs on `ToolSpec`.
- `core.Manifest` / `ManifestTool` / `ManifestAck` / `ManifestPolicy`
  (`sdk-go/pkg/core/manifest.go`) exist; the ack already carries a policy
  echo, and `config_version` on the heartbeat already triggers a re-read
  (`ManifestStateReader`). Settings ride the same rails.
- The tool wrappers move from sdk-go into `sensor/internal/…` (sensor#112,
  sdk-go v0.16.0 deprecations). Schemas will be written next to them.
- sdk-go is adding `docs/STABILITY.md` and a platform `features` list for
  negotiation; this RFC adds the feature name `tool_settings`.
- The api has `secretstore.Encryptor` (AES-256-GCM, key rotation through
  `APP_ENCRYPTION_KEY_PREVIOUS`) and a hash-chained audit log
  (`auditService.LogSensorUpdated`).
- RFC-032 gives each enrolled sensor an Ed25519 signing key and an X25519
  encryption key, and pins the platform's job-signing root at enrollment.
- The web app uses `react-hook-form` 7 with `@hookform/resolvers`, shadcn/ui
  components (`web/src/components/ui/form.tsx`, `input`, `select`,
  `switch`, `slider`…) and has `edit-sensor-dialog.tsx` and
  `sensor-detail-sheet.tsx` under `web/src/features/sensors/`.
- Sensors are admin-only to change (authz audit #2); custom scanner
  templates are owner/admin-only (api#773).

## 4. Design principles

| Principle | What we take |
|---|---|
| The tool owns a typed schema (typed attributes, required/optional, sensitive, validators, defaults, descriptions, deprecation); the platform renders it and does not invent one | The tool owns a typed schema; `sensitive`; per-field description and deprecation. |
| Structural (closed) schemas with server-side defaulting and cross-field policy rules that carry messages and transition rules | Structural schemas, server-side defaulting, CEL for cross-field and policy rules with messages, transition rules (e.g. a value may only decrease). We **reject** unknown keys rather than prune them, because a silently dropped scan option is the bug we have today. |
| A non-Turing-complete, cost-estimable, sandboxed expression language with no I/O | Why CEL for S5. |
| Secrets are write-only: stored encrypted, never returned to the browser; the UI is told a secret is set without revealing it | Write-only secret fields, "set / not set" indicator, "replace" instead of "show". |
| Validation is the component's job, and both sides validate with the same schema | The sensor validates with the same schema it published, so the two sides cannot disagree. |
| Two scopes: process-level config and per-task config | Sensor-level and scan-level settings (`x-octm-scope`). The platform validates before dispatch. |
| **ProjectDiscovery tools** [1]: nuclei/httpx read YAML config files with precedence built-ins < system < user < selected config < CLI. Options include `rate-limit`, `concurrency`, `bulk-size`, `severity`, `tags`, `exclude-tags`, `interactsh-server`, `proxy`, `headless`. | Typed options for the safe subset; `proxy`, `interactsh-server`, `templates`, `headless` stay platform-controlled (RFC-034, RFC-036 tiers), not settings. We pass flags, not config files, so `-config` stays blocked (`DangerousToolFlags`). |
| **JSON Schema 2020-12** [2]: Validation keywords (`type`, `enum`, `const`, bounds, `pattern`, `required`, `additionalProperties`) and annotations (`title`, `description`, `default`, `deprecated`, `readOnly`, `writeOnly`, `examples`). | The base vocabulary; `writeOnly` for secrets; `deprecated` for evolution. |
| **JSON Forms** [3] / **react-jsonschema-form** [4]: Generate forms from a data schema plus a UI schema, validate with Ajv. RJSF ships a **shadcn theme** (`@rjsf/shadcn`). | Generate forms from the schema; see §6.9 for why we render our own small renderer instead of adding RJSF. |
| **The Update Framework** [5]: Signed metadata with version numbers (no rollback), expiry (no freeze attack), role-separated keys. | Signed settings document with monotonic `version` and an optional `expires_at`; the signing key is the pinned job-signing root. |
| **OPA / Rego** [6]: General policy engine, sidecar or library, Rego language. | Considered for S5, not chosen (§9). |

## 5. Trust and threat model

| # | Threat | Today | With this RFC | Residual |
|---|---|---|---|---|
| T1 | Admin (or stolen admin session) injects a CLI flag via a settings value | free-form `scanner_config` + denylist | no free-form strings reach argv: each option is typed and mapped to fixed flags by the adapter (S8); strings are bounded by `pattern`/`maxLength`; argv still passes `ValidateExtraArgs` | a schema author (sensor developer) could map an option to a dangerous flag: code review of `sensor/internal/…`, `ValidateExtraArgs` backstop |
| T2 | Non-admin user changes a sensor's behaviour | — | `sensors:write` is owner/admin only; scan-level overrides only for `scope: scan` keys and still checked by policy | — |
| T3 | Member raises intrusiveness via a scan override (e.g. turns on interactsh) | `allow_interactsh` in the command config | the key's `x-octm-tier: T2` and CEL policy refuse it unless the scan target is T2-approved (RFC-036 O3) | — |
| T4 | Compromised platform / MITM pushes hostile settings | — | the sensor validates against its **own** schema (bounds still hold); document signed by the pinned job-signing key (S6); `version` monotonic | a fully compromised platform with the signing key can still choose any in-schema value: schemas must not offer dangerous ranges |
| T5 | Rollback to an older, weaker document | — | sensor refuses `version` ≤ stored | — |
| T6 | Secret leaks through API, UI, logs, backups or other sensors | `scanner_config` in clear | write-only in API/UI; AES-GCM at rest with the tenant key; HPKE-sealed to the target sensor in transit; values redacted in audit diffs and logs; stored on the sensor 0600 | secret is in memory and in the tool's argv/env while it runs; prefer env (not argv, visible in `ps`) — adapter rule |
| T7 | Malicious sensor publishes a schema to phish values (e.g. a field titled "AWS secret key") | — | schemas come only from approved sensors (RFC-032); the UI shows the tool and sensor version that declared a field; secret fields from a sensor are bound to that sensor only (sealed to its key) | an admin may still type a secret into a field a hostile sensor asked for: approval is the gate |
| T8 | Oversized or pathological schema / value DoS | — | limits: schema ≤ 32 KiB, ≤ 64 properties per tool, depth ≤ 2, `pattern` ≤ 256 chars compiled with RE2 (Go `regexp`, linear time), document ≤ 64 KiB; CEL cost limit | — |
| T9 | Drift: sensor silently runs other settings than shown | — | sensor reports applied `version` + `digest` + rejection reasons; UI shows "pending / applied / rejected" | an offline sensor runs the last applied version until it reconnects (by design) |

## 6. Design

### 6.1 The schema (sensor side, per tool)

A tool's schema is a JSON object. Example for nuclei (abridged):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 3,
  "title": "nuclei",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rate_limit": {
      "type": "integer", "minimum": 1, "maximum": 1000, "default": 150,
      "title": "Requests per second",
      "description": "Upper bound on HTTP requests per second (nuclei -rate-limit).",
      "x-octm-scope": "scan", "x-octm-group": "Performance", "x-octm-order": 10
    },
    "concurrency": {
      "type": "integer", "minimum": 1, "maximum": 100, "default": 25,
      "title": "Templates in parallel", "x-octm-scope": "sensor",
      "x-octm-group": "Performance"
    },
    "severity": {
      "type": "array", "uniqueItems": true, "maxItems": 5,
      "items": { "enum": ["info", "low", "medium", "high", "critical"] },
      "default": ["low", "medium", "high", "critical"],
      "title": "Severities", "x-octm-scope": "scan"
    },
    "exclude_tags": {
      "type": "array", "maxItems": 64,
      "items": { "type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$" },
      "title": "Excluded template tags", "x-octm-scope": "scan"
    },
    "interactsh": {
      "type": "boolean", "default": false, "title": "Out-of-band checks (Interactsh)",
      "x-octm-scope": "scan", "x-octm-tier": "T2"
    }
  }
}
```

Allowed keywords (anything else makes the schema invalid on **both** sides):
`$schema`, `title`, `description`, `type` (`object` root; properties:
`boolean`, `integer`, `number`, `string`, `array` of a scalar or enum),
`enum`, `const`, `default`, `minimum`, `maximum`, `exclusiveMinimum`,
`exclusiveMaximum`, `multipleOf`, `minLength`, `maxLength`, `pattern`
(RE2), `format` (`hostname`, `uri`, `duration`), `items`, `minItems`,
`maxItems`, `uniqueItems`, `properties` (one nested object level for
grouping), `required`, `additionalProperties: false` (mandatory),
`deprecated`, `writeOnly`, `examples`, and the `x-octm-*` annotations:

| Annotation | Meaning |
|---|---|
| `x-octm-schema-version` | integer, increases when a key is removed or narrowed (S12) |
| `x-octm-scope` | lowest level allowed to set the key: `sensor` (sensor settings only) or `scan` (sensor, scan profile and scan). Default `sensor` |
| `x-octm-tier` | minimum tier (`T0`, `T1`, `T2`) whose policy permits a non-default value |
| `x-octm-sensitive` | secret: implies `writeOnly`; stored encrypted, sealed in transit, never returned, never logged |
| `x-octm-restart` | `true` if applying needs the tool's long-lived process restarted (none today: every scan is a new process) |
| `x-octm-group`, `x-octm-order`, `x-octm-widget` | UI only: section, order, widget hint (`slider`, `textarea`, `tags`) |

Why a subset: everything in it is easy to validate identically in Go (api
and sensor) and to render; `$ref`/`oneOf`/conditionals make forms and error
messages hard and would let a schema hide fields from review.

### 6.2 SDK types (sdk-go, additive)

```go
// pkg/core/settings.go
type SettingsSchema struct {
    Raw     json.RawMessage // the schema document as declared
    Version int             // x-octm-schema-version
}
func (s SettingsSchema) Digest() string              // "sha256:" + canonical JSON
func ParseSettingsSchema(b []byte) (*SettingsSchema, error) // enforces §6.1 subset + limits
func (s *SettingsSchema) Validate(values map[string]any) error // typed, rejects unknown keys
func (s *SettingsSchema) Defaults() map[string]any

// ToolSpec gains one optional field:
type ToolSpec struct { /* … */ Settings *SettingsSchema }

// ManifestTool gains:
type ManifestToolSettings struct {
    SchemaVersion int    `json:"schema_version"`
    Digest        string `json:"digest"`
}
// ManifestTool.Settings *ManifestToolSettings `json:"settings,omitempty"`

// What a tool receives at run time:
type ToolSettings interface {
    Int(key string) (int64, bool)
    Bool(key string) (bool, bool)
    String(key string) (string, bool)
    Strings(key string) ([]string, bool)
    Secret(key string) ([]byte, bool) // opened from the sealed blob, never logged
    Source(key string) SettingSource   // default | sensor | profile | scan
}
// ScanOptions gains Settings ToolSettings (nil: tool defaults, as today).

// Delivery and store
type SensorSettings struct { /* §6.6 */ }
type SettingsStore interface { Load() (*SensorSettings, error); Save(*SensorSettings) error }
func NewFileSettingsStore(dir string) SettingsStore // 0600, temp+fsync+rename
```

A JSON Schema validator library is **not** needed: the subset is small
enough to validate with ~300 lines of Go. The api does not import sdk-go
(RFC-002 decoupled them; it imports only `ctis`), so the api keeps its own
copy of the validator. The two cannot drift because both run the **same
golden vectors** (`testdata/settings-vectors/*.json`: schema, values,
expected result and error path), copied byte for byte and compared by a
security-lint rule, as Rule 6 already does for the httpsec tables (O9).

### 6.3 Registration (manifest, digest-addressed)

1. The sensor's adapter attaches `Settings` to its `ToolSpec`. The sensorkit
   puts `{schema_version, digest}` per tool in the manifest (RFC-033 §6.2),
   so the manifest digest changes when a schema changes.
2. Hello advertises feature `tool_settings`. If the platform does not list
   it in its `features`, the sensor stops here (no form; tool defaults).
3. After `PUT /api/v2/sensor/manifest`, the ack lists
   `missing_tool_schemas: [digest…]`; the sensor uploads them with
   `PUT /api/v2/sensor/tool-schemas` (body: `[{tool, digest, schema}]`).
   The platform verifies each digest, parses with `ParseSettingsSchema`
   (same limits), and stores it once (content-addressed, shared by every
   sensor with the same build).
4. A heartbeat answer may carry action `send_tool_schemas` (e.g. after a
   database restore), like `send_manifest`.

### 6.4 Platform storage (api)

```
tool_settings_schemas   (digest PK, tool, schema_version, schema jsonb,
                         first_seen_at, first_sensor_id)
sensor_tool_settings    (tenant_id, sensor_id, tool, values jsonb,          -- non-secret
                         secret_values bytea,                              -- AES-GCM, tenant key
                         schema_digest, updated_by, updated_at,
                         PRIMARY KEY (sensor_id, tool))
sensor_settings_state   (sensor_id PK, desired_version bigint, desired_digest,
                         applied_version, applied_digest, applied_at,
                         status  -- pending | applied | rejected
                         , errors jsonb)
```

Scan-profile and scan overrides stay where they are
(`scan_profiles.tools_config[tool].options`, scans' `scanner_config`) but
are validated against the schema of the dispatched sensor's tool at
dispatch, and only `scope: scan` keys are accepted there. The old
`tools.config_schema` / `tenant_tool_configs.config` columns are left
untouched and documented as legacy (removal is a separate cleanup).

### 6.5 API and permissions

| Route | Permission | Notes |
|---|---|---|
| `GET /api/v1/sensors/{id}/tool-settings` | `sensors:read` | per tool: schema, effective values with source, secrets as `{"set": true}` only, desired vs applied state |
| `PUT /api/v1/sensors/{id}/tool-settings/{tool}` | `sensors:write` (owner/admin) | body `{values, secrets?: {key: value|null}, expected_version}`; optimistic concurrency on `desired_version`; `null` clears a secret |
| `POST /api/v1/sensors/{id}/tool-settings/{tool}:validate` | `sensors:write` | dry run: returns errors and the diff for the confirm step |
| `DELETE /api/v1/sensors/{id}/tool-settings/{tool}` | `sensors:write` | reset to tool defaults |
| `GET /api/v2/sensor/settings` (sensor) | sensor auth (signed request) | current signed document; `If-None-Match` on digest |
| `POST /api/v2/sensor/settings/status` (sensor) | sensor auth | `{version, digest, status, errors}` |

Write path: authz → load schema for the sensor's current tool digest →
`Validate` (types, bounds, unknown keys) → CEL policy (§6.7) → encrypt
secrets → bump `desired_version` → audit `sensor.tool_settings.updated`
with a diff where secret values are `"<redacted>"` → bump the sensor's
`config_version` so its next heartbeat fetches.

### 6.6 Delivery and the sensor side

Document (canonical JSON, then signed):

```json
{
  "kind": "openctem.sensor.settings/v1",
  "sensor_id": "…", "tenant_id": "…",
  "version": 42, "issued_at": "2026-10-02T10:00:00Z",
  "tools": {
    "nuclei": {
      "schema_digest": "sha256:…",
      "values": { "rate_limit": 50, "severity": ["high", "critical"] },
      "sealed_secrets": "<HPKE ciphertext, base64, aad = sensor_id|version|tool>"
    }
  },
  "signature": { "alg": "Ed25519", "keyid": "<job-signing root thumbprint>", "sig": "…" }
}
```

Sensor steps (SDK, sensorkit):

1. Heartbeat answer's `config_version` moved → `GET /api/v2/sensor/settings`.
2. Verify the signature with the pinned job-signing root (RFC-032 T7). If
   the platform has not shipped signing yet, accept on the authenticated v2
   channel and log `settings_unsigned` once.
3. Refuse if `sensor_id` is not ours or `version` ≤ the stored version.
4. For each tool: the `schema_digest` must equal the digest of the schema
   **this** sensor build declares; then `Validate(values)`; open
   `sealed_secrets` with the sensor's X25519 key. Any failure rejects that
   tool's block (others still apply) and is reported.
5. Save atomically (`SettingsStore`, 0600 file in `/var/lib/openctem/state`,
   dir 0700, temp + fsync + rename), sealed secrets stay sealed on disk and
   are opened per job.
6. New jobs read the stored document; running jobs keep what they started
   with. The job's command result records the settings version it ran with.
7. `POST /api/v2/sensor/settings/status` with the outcome; the heartbeat
   also echoes `settings_version` so the platform sees drift even if the
   POST was lost.

An offline sensor runs its last applied version and converges on
reconnect. A sensor upgraded to a build whose schema digest differs reports
`rejected: schema_mismatch` for that tool until the platform re-validates
the stored values against the new schema (§6.10) and issues a new version.

### 6.7 Policy constraints (CEL)

Built-in rules (code, always on):

- a value different from the default for a key with `x-octm-tier: T2` is
  allowed only when the sensor's zone / the scan's target is approved for
  T2 (RFC-036 O3); `T1` likewise;
- `x-octm-scope: sensor` keys are refused in scan profiles and scans;
- secret keys only for `key_bound`+ sensors (RFC-032 assurance).

Tenant rules (later phase), stored per tenant, evaluated with cel-go with a
cost limit, variables `tool`, `values`, `old` (previous values), `sensor`
(zone, tier, labels), `scope`:

```
tool == "nuclei" && sensor.zone == "prod" ? values.rate_limit <= 50 : true
```

Each rule has a `message`; failures return 422 with the rule's message.

### 6.8 Secrets

- Declared with `x-octm-sensitive: true` (implies `writeOnly`).
- API never returns them; responses carry `{"set": true, "updated_at"}`.
- Stored AES-256-GCM with `secretstore.Encryptor` (tenant key, rotation via
  previous keys).
- Sealed per document to the sensor's X25519 key with HPKE (RFC 9180,
  RFC-032 E10), AAD binds sensor, version and tool, so a blob cannot be
  replayed to another sensor or version.
- Adapters pass secrets by environment variable or a 0600 temp file, never
  argv (visible in `ps`); logs and audit redact them.
- Legacy `rda_` sensors get no secret settings (the form says why).

### 6.9 UI (web)

- Sensor detail sheet gains a **Tool settings** tab; the add/edit sensor
  dialog links to it after the sensor's first manifest (a new sensor has no
  schema until it connects — the form says "available once the sensor
  connects").
- A small renderer maps the §6.1 subset to existing shadcn components
  (`Input`, `Switch`, `Select`, `Slider`, `tag-input`,
  `Textarea`) inside `react-hook-form`; validation errors come from the
  server's dry-run endpoint, plus client-side checks generated from the
  same schema (bounds, pattern, enum) for instant feedback.
- Recommendation: **our own renderer (~400 lines) rather than
  `@rjsf/shadcn` or JSON Forms.** The subset is small, we already use
  react-hook-form + shadcn, and a full JSON Schema form library would
  re-introduce the features we excluded (`oneOf`, `$ref`) and Ajv on the
  client. If the subset grows, `@rjsf/shadcn` is the fallback (it exists and
  fits the stack).
- Each field: title, description, default ("Default: 150"), source badge
  (default / sensor / profile / scan), "Reset to default", deprecated
  marker. Secret fields: "Set" / "Not set", "Replace", "Clear".
- Save shows a diff (old → new, secrets as "changed") and requires
  confirmation; status chip "Pending / Applied v42 / Rejected (reason)".
- Scan-profile and scan forms show only `scope: scan` keys of the tools they
  use, with the sensor-level value as placeholder.

### 6.10 Schema evolution and compatibility

- **Adding** an optional key with a default: same `schema_version`; old
  stored values stay valid; old sensors ignore it (they never see it: the
  platform validates against the schema of the sensor's own build).
- **Removing / narrowing** a key: bump `x-octm-schema-version`; on the next
  manifest the platform re-validates stored values against the new schema,
  drops removed keys (audited as `migrated`), and marks out-of-range values
  `invalid` for the admin to fix; until fixed, that tool runs with defaults
  for those keys and the UI flags it.
- **Deprecated** keys (`deprecated: true`) stay accepted for one minor sensor
  release, shown struck-through.
- **Mixed fleets:** values are stored per sensor, validated against that
  sensor's schema digest, so two sensor versions with different schemas
  coexist.
- **No schema** (old sensor, or platform without `tool_settings`): no form,
  tool defaults, nothing pushed; everything else unchanged.

### 6.11 What is deliberately **not** a setting

`proxy` / egress (RFC-034 profiles), interaction server URL, template paths
or URLs, custom templates (api#773, admin-only), output paths, resolvers,
headless browser, scan credentials (RFC-032 E10), free-form extra args.
These are either platform-controlled per job or security boundaries.

### 6.12 Custom template trust (implemented 2026-10-03)

> Amended 2026-10-09 (RFC-040 §11.5): with the job signer, a template
> version reaches sensors only once approved like a scope widening and
> recorded in the signer's ledger; the signed job lists the template
> digests and a sensor that verifies it trusts them through the job. The
> per-tenant manifest below is the fallback for sensors without signed
> jobs ([job-signing.md, "Custom templates"](../architecture/job-signing.md#custom-templates)).

Custom templates are not settings (§6.11), but they reach the sensor the
same way settings will, so they get the delivery guarantees first: DSSE
over the exact bytes, tenant and sensor binding, expiry, one manifest per
set, a sensor-side capability fence, and nuclei's own template trust.

**Upload (api).** `NucleiValidator` refuses, on the parsed document (any
YAML or JSON spelling, any key case), templates that use the `code` or
`javascript` protocol (run code on the sensor), `headless` (drives a
browser) or `file` (reads the sensor's disk), and self-contained templates
(carry their own targets). The error names the protocol, e.g.
`code: the "code" protocol runs code on the scanner and is not allowed in
custom templates`. Same validator for create, update, template-source sync
and inline command templates. Uploading stays admin-only (api#773).

**Delivery (api).** Every poll (`command.Service.Poll`, v1 and v2) re-signs
the custom templates of each command it returns, on a copy (the stored
command never changes): `template.PayloadSigner` validates every template
again and seals one manifest of the set:

```json
{"kind": "openctem.template-manifest/v1",
 "tenant_id": "<command tenant>", "sensor_id": "<polling sensor>",
 "command_id": "<command>", "issued_at": "…", "expires_at": "<issued + 1h>",
 "templates": [{"id": "…", "name": "…", "template_type": "nuclei",
                "sha256": "<hex of the decoded content>"}]}
```

in a DSSE envelope (`custom_templates_envelope`: `payloadType`
`application/vnd.openctem.template-manifest+json`, `payload` = the exact
signed bytes, `signatures[{keyid, sig}]`, Ed25519 over the DSSE v1
pre-authentication encoding). JSON is never canonicalised: the sensor
checks the bytes it received. If any template fails validation the set is
sent with no manifest and the sensor refuses the command. A manifest the
payload already carried is always dropped.

**Keys.** One Ed25519 key per tenant, derived with HKDF-SHA256 from a
32-byte master: `APP_TEMPLATE_SIGNING_KEY`, or (unset) a value derived
from `APP_ENCRYPTION_KEY` with its own HKDF label. A tenant admin reads the
public key at `GET /api/v1/scanner-templates/signing-key`
(`scanner_templates:read`; it is public) and pins it on the tenant's
sensors in `SENSOR_TEMPLATE_SIGNING_KEYS` (several keys, comma-separated,
for a rotation). A tenant's key never verifies another tenant's manifest.

**Sensor (sdk-go `core.TemplateVerifier`, sensor nuclei wrapper).** Before
anything is written: verify the envelope signature over the exact payload
bytes with a pinned key, then parse (unknown fields refused) and refuse
another payload type or kind, another command, another sensor (when
`SENSOR_ID` is set), an expired manifest or one issued in the future (5
minutes skew), and any template changed, added, held back or reordered.
No pinned key or no manifest: the command fails (fail closed). The sensor
then checks the templates itself (`CheckCustomTemplates`: no code,
javascript, file, headless or self-contained) and runs them in their own
nuclei run with `-exclude-type code,file,headless,javascript`, never
`-code`, `-file`, `-headless` or `-esc`; the sensor's own (ProjectDiscovery
signed) templates run separately and always with
`-disable-unsigned-templates`. These flags, `-dut=false` included, are
refused in extra args (`core.DangerousToolFlags`): no pushed content can
switch them on, and the server has no "force" bypass.

**Rate limits (RFC-034 §2.1).** A scan command may ask for lower
`rate_limit`, `concurrency` and `bulk_size` (whole numbers); the sensor
caps them at `SENSOR_NUCLEI_MAX_RATE_LIMIT` / `_CONCURRENCY` /
`_BULK_SIZE` (default 150 / 25 / 25) and always passes `-rate-limit`,
`-c`, `-bs`. Rate-limit flags in extra args are refused
(`core.RateLimitToolFlags`).

| Threat | Control | Residual |
|---|---|---|
| Malicious tenant admin uploads a code/file/headless/JS template | refused at upload and at every delivery; the sensor re-checks and nuclei excludes the types | a template using only allowed protocols (http, dns, network, ssl, websocket, whois) still sends what its author wrote to in-scope targets: that is what a custom template is |
| Compromised API (or its signing key) pushes templates | the sensor's own fence holds: no code, file, headless, JS or self-contained templates, no `-code`; targets still pass the sensor's SSRF guard; rate ceilings hold | it can sign any allowed-protocol template for its tenants' sensors until the key is rotated and re-pinned |
| Write to the DB or command queue (SQL injection, stolen DB creds) | delivery re-validates and signs only what passes; a forged or stale envelope is dropped | same as above for allowed protocols |
| MITM on the control channel | Ed25519 over the exact bytes with a key pinned out of band; command/sensor binding; expiry | none for template content; a MITM can still drop commands |
| Replay of a captured command to another sensor or later | manifest bound to command and (with `SENSOR_ID`) sensor; 1 h expiry | replay to the same sensor within the hour re-runs an approved set |
| Tenant raises the rate limit to DoS a target | ceilings on the sensor, typed values only, rate flags refused in extra args | an operator who owns the sensor sets the ceiling |

**Follow-ups (not built yet).**

1. Monotonic `version` with a persisted floor for persistent sets (the
   settings document of §6.6 and any cached template set). Per-command
   manifests use command binding and expiry instead, because commands run
   concurrently and arrive out of order.
2. TUF-style key hierarchy: an offline threshold root that delegates to the
   online signing key and can revoke it (go-tuf v2), replacing out-of-band
   pinning and manual rotation; RFC-032's enrollment-pinned job-signing root
   is the natural home.
3. Sensor identity from RFC-032 enrollment, so every sensor (not only those
   with `SENSOR_ID`) checks the `sensor_id` binding.
4. A sensor-local enable switch for any future high-risk
   capability (headless, DAST) rather than code-level defaults.
5. A key-rotation runbook and a UI field showing the key to pin; reporting
   template-verification failures as a distinct command error code.

## 7. Compatibility

- Additive on every wire: new manifest field, new endpoints, new heartbeat
  echo, new feature name. Unknown fields are ignored on both sides.
- `ScanOptions.Settings` nil means "today's behaviour".
- `scanner_config` / profile `options` keep working for the keys the SDK
  already honours (`allow_interactsh`, `exclude`); other free-form keys are
  validated against the schema when the dispatched sensor has one, and
  refused with a clear error (instead of silently ignored) — a deliberate,
  visible behaviour change, called out in release notes.

## 8. Phased plan

| Phase | Repo | Work | Size |
|---|---|---|---|
| P0 | sdk-go | `SettingsSchema` (parse subset + limits, validate, defaults, digest) with the golden vectors, `ToolSpec.Settings`, `ManifestTool.Settings`, `ToolSettings`, `ScanOptions.Settings`, `SettingsStore` (file, 0600 atomic), feature `tool_settings`; conformance fake serves the new routes | M |
| P1 | sensor | schemas + typed mapping for nuclei, trivy, semgrep, betterleaks (in `internal/…` after the move); tests that each option produces exactly the expected argv and passes `ValidateExtraArgs` | M |
| P2 | api | validator copy passing the same golden vectors + security-lint parity rule, migrations for §6.4, upload/fetch routes, admin routes with validation + built-in policy + audit, `config_version` bump, document signing (when the RFC-032/023 signing key exists; else unsigned on the authenticated channel), status ingest, dispatch-time validation of scan overrides | M–L |
| P3 | web | Tool settings tab, renderer, diff/confirm, status chip, scan-profile/scan `scope: scan` fields | M |
| P4 | sensor + api | recon tools (subfinder, dnsx, httpx, naabu, katana) after the move; secrets (HPKE) once RFC-032 Phase 3 lands; tenant CEL rules; e2e test (admin sets nuclei rate limit → sensor applies → job argv shows it → status applied) | M |

## 9. Alternatives considered

| Alternative | Why not |
|---|---|
| Keep free-form `scanner_config` with a better denylist | Denylists fail open: every new flag or tool is unsafe until someone lists it. The typed allow-list is the fix. |
| Ship tool config files (nuclei `-config`) from the platform | A config file can set anything the tool supports, including proxies, template paths and output; it re-opens what `DangerousToolFlags` closes. |
| Full JSON Schema + Ajv + RJSF | Larger attack and review surface (`$ref`, `oneOf`, remote refs), two validators that can disagree (Ajv in JS, another in Go). The subset is validated by one Go implementation shared by api and sensor. |
| Protobuf / CUE for schemas | Strong typing, but no UI metadata convention and a new toolchain for sensor authors; JSON Schema is what form generators and humans already read. |
| OPA/Rego for policy | Another language and (usually) another service; our rules are small expressions over one document. CEL is embedded and cost-bounded. |
| Settings in heartbeats | Heartbeats must stay small (RFC-033, RFC-035); settings change rarely. `config_version` + fetch is the existing pattern. |
| Sensor-local only (env / file on the host) | That is today; the requirement is platform-managed settings. Host env stays as the operator's override for content/egress settings that are explicitly host-owned (RFC-034 O1). |

## 10. Open decisions (recommendations in bold)

| # | Question | Options | Recommendation |
|---|---|---|---|
| O1 | Unknown keys arriving at the sensor | (a) reject the tool's block; (b) drop and continue (prune) | **(a)**: a dropped option is the silent-failure class we keep fixing |
| O2 | Integrity of the settings document | (a) Ed25519-signed by the platform job-signing key (requires RFC-023 P6 / RFC-032 pinned root); (b) HMAC with a per-sensor secret; (c) rely on authenticated TLS + signed request only | **(a) when the key exists, (c) until then**; (b) adds a second secret to manage for no gain once (a) exists |
| O3 | Policy rules | (a) built-in rules only; (b) + tenant CEL rules; (c) OPA | **(a) in P2, (b) in P4** |
| O4 | Form rendering | (a) own renderer over shadcn; (b) `@rjsf/shadcn`; (c) JSON Forms | **(a)** |
| O5 | Who may set scan-level overrides of `scope: scan` keys | (a) whoever may create the scan/profile; (b) admins only | **(a)**, bounded by the schema and tier policy |
| O6 | Secret settings before RFC-032 Phase 3 (HPKE) | (a) not supported until then; (b) send over TLS to key-bound sensors | **(a)** |
| O7 | Free-form `scanner_config` keys not in a schema | (a) refuse at dispatch when the sensor has a schema; (b) keep ignoring silently | **(a)**, with release notes |
| O8 | Sensor-level vs zone-level defaults | (a) per sensor only; (b) also per zone (inherit) | **(a) now**, (b) later if fleets grow (zones already group sensors) |
| O9 | One validator for api and sensor | (a) separate Go copies in api and sdk-go, held identical by shared golden vectors + a security-lint parity rule; (b) a shared module (e.g. a package in `ctis`, which both already import); (c) api imports sdk-go | **(a)**: keeps RFC-002's decoupling and `ctis` on topic; (b) if a third consumer appears |

## 11. Sources

1. ProjectDiscovery nuclei, running and configuration: https://docs.projectdiscovery.io/tools/nuclei/running
2. JSON Schema 2020-12 Validation (incl. `deprecated`, `writeOnly`): https://json-schema.org/draft/2020-12/json-schema-validation
3. JSON Forms: https://jsonforms.io/docs/
4. react-jsonschema-form, themes (incl. `@rjsf/shadcn`): https://rjsf-team.github.io/react-jsonschema-form/docs/usage/themes
5. The Update Framework, overview: https://theupdateframework.io/docs/overview/
6. Open Policy Agent: https://www.openpolicyagent.org/docs/latest/
