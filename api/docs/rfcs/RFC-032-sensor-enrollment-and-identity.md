# RFC-032 — Sensor enrollment, identity and declared capabilities

> Status: **Accepted** (2026-10-02; owner decisions in §10.1). Proposed
> 2026-10-02 in #706. Phase 0 is in implementation.
> **Revised 2026-10-03** (§10.4): credential prefixes are `octs_` (sensor API
> key, now issued) and `octe_` (enrollment token, replacing the proposed
> `ocse_`), both with a base62 CRC32 checksum; `rda_` is legacy and is retired
> **90 days after enrollment and key-bound identity (Phases 1 and 2) ship**,
> replacing the 2027-04-01 date in D3.
> Scope: api + sdk-go + sensor (`openctemio/sensor`, local checkout `agent`) +
> ui + helm-charts.
> Builds on and makes concrete: [RFC-014](RFC-014-agent-identity.md) (per-sensor
> keys, expiry, renewal, overlap; its open Phases 4 and 5),
> [RFC-023](RFC-023-scan-zones-and-scanners.md) (D10 enrollment + approval,
> D16 `sensors:approve`, D20 capability negotiation, D22 trust tiers, §4b
> P1–P4 key-bound identity), [RFC-026](RFC-026-sensor-results-ingest.md)
> (iteration 2: the RFC 9421 profile), [RFC-029](RFC-029-sensor-protocol-v2-and-sdk-stability.md)
> (protocol v2, `POST /keys`, §4.3.1 sensor-reported capabilities, the
> planned `sensorkit` facade, the v1 sunset 2027-04-01) and
> [RFC-031](RFC-031-managed-sensor-updates.md) (signed images; platform
> compromise). Where this RFC and RFC-023 §4b differ, this RFC is the more
> specific decision and RFC-023 is amended by reference.
> Mutual distrust: [RFC-040](RFC-040-platform-sensor-mutual-distrust.md)
> treats Phases 1–2 of this RFC as its P0 dependency (signed jobs and the
> object checks bind to the per-sensor key) and records the owner decisions
> of 2026-10-03 (§5.2 there): `octs_` interim sensor key and `octe_`
> enrollment token, and the bearer-key sunset 90 days after Phases 1–2 ship
> instead of 2027-04-01.
>
> Owner's question (2026-10-02): today an administrator pre-creates a sensor
> in the UI (name, role, tool chips), receives a long-lived `rda_…` key shown
> once and pastes it into a docker / compose / Kubernetes / Helm command.
> "The platform cannot know which tools a third-party sensor has, only the
> sensor can say. Research thoroughly and give the best, most modern, most
> secure option."

## 1. Answer in short

**Stop creating sensors in the UI. Create an *enrollment token* instead, and
let the sensor create itself.**

| | Today | After this RFC |
|---|---|---|
| What the administrator makes | a sensor record (name, role, tools) | an **enrollment token**: tenant + role, optional zone, tags, tool ceiling, uses, expiry, approval mode |
| What the install command carries | a long-lived sensor key | a short-lived, use-limited enrollment token (`ocse_…`), worthless once used |
| Who generates the credential | the platform, then shows it to a human | the **sensor**, on its own host: an Ed25519 key pair; the private key never leaves the host and never passes through a human, a browser, a shell history or a CI log |
| What goes on the wire per request | the bearer key (`Authorization: Bearer rda_…`) | an **RFC 9421 HTTP Message Signature** (Ed25519) over method, URI, `Content-Digest`, `created`, `nonce`; no bearer secret at all |
| What the platform knows about tools | what a human typed (and since RFC-029 §4.3.1, the sensor's report ∩ that list) | the sensor's report, from the first request (enrollment), narrowed by the token's policy; the admin types nothing |
| Joining | always a human with a key | token (any host), or **keyless** for Kubernetes (projected service-account token), CI (GitHub/GitLab OIDC) and clouds (instance identity), where no secret exists at all |
| Approval | none (a key is trust) | per token: single-use tokens are pre-approved (the admin just made them); reusable tokens put new sensors in **Pending approval** with their key fingerprint |
| Rotation / revocation | manual regenerate; key TTL and auto-renew exist but are off by default on every install path, so keys never expire in practice (§3.3) | automatic key rotation (30 days, signed by the old key), revocation checked on every request |
| Leaked credential | valid until noticed | a copied enrollment token after use: nothing; a copied private key: detected as a **cloned identity** (two live instances) and quarantined |
| Existing `rda_` sensors | — | keep working; **a sensor upgraded to the new SDK upgrades itself** (generates its key, registers it with its `rda_` key, the server retires the `rda_` key). "Bump the SDK and done." |

Capabilities stay what RFC-029 §4.3.1 made them: **a claim from the sensor,
which policy can only narrow**. This RFC adds the honest part: a sensor's
report says what it *can* run, never what it *is*. No software-only signal
(image digest, SDK version, tool versions) proves that a host runs our build;
only third-party attestation (Kubernetes, cloud, CI OIDC; later a TPM) binds
facts the sensor cannot invent. So the decision that matters, *which sensors
may receive scan credentials*, is made on identity strength and approval,
and credentials are **sealed to the sensor's key** (HPKE), never sent in
clear inside a job.

## 2. Decisions

| # | Decision |
|---|---|
| E1 | **Enrollment, not pre-creation, is the primary flow.** The UI's "Add sensor" creates an enrollment token; nothing is created until a sensor enrolls. Pre-creating a sensor with a key remains only behind "Legacy key (for sensors on an SDK without enrollment)" until the v1/`rda_` sunset. |
| E2 | **Enrollment token** `ocse_<id>_<secret>`: 128-bit id for lookup, 256-bit secret, CRC32 checksum suffix (leak scanners can validate it offline), stored as HMAC-SHA256 with the sensor-credential pepper (as `rda_` keys are; Phase 0 stops reusing `APP_ENCRYPTION_KEY` as that pepper, §3.1 G9). The token is a public id plus a secret. Policy on the token: tenant, role, zone(s), tags, tool/capability ceiling, `max_uses` (default 1), `expires_at` (default 60 min, max 30 days for reusable), approval mode, `ephemeral`, name template. Revocable; every use is audited. |
| E3 | **Approval:** single-use tokens default to **auto-approve** (creating the token *was* the human decision and it expires within the hour). Reusable tokens default to **manual approval**: the sensor appears as *Pending approval* with hostname, IP, OS/arch, versions, reported tools and its **key fingerprint**, which the sensor also prints in its log, so the admin can compare (as with an SSH host key). A pending sensor can heartbeat but receives no jobs, content, credentials or configuration. |
| E4 | **Sensor identity = an Ed25519 key pair generated by the sensor**, stored 0600 in the sensor's persisted state volume (`/var/lib/openctem/state/identity/`), or supplied by a mounted file / Kubernetes Secret / OS keystore; TPM-backed keys later. Only the public key (JWK, RFC 7517/8037) and its thumbprint (RFC 7638) are sent. |
| E5 | **Every v2 request is signed** per the RFC-026 §4 iteration-2 profile (RFC 9421, `alg="ed25519"`, `keyid` = key thumbprint, `created`, `expires` ≤ 300 s, `nonce`, covered `@method @target-uri content-type content-digest`). No bearer secret is presented once a key is registered; the server refuses the `rda_` key for that sensor afterwards. Chosen over mTLS as the default because it survives TLS-terminating gateways, load balancers and **corporate egress TLS inspection**, which breaks client certificates (§5.2). mTLS stays an optional high-assurance mode (Phase 5). |
| E6 | **Proof of possession at enrollment.** `POST /api/v2/sensor/enroll` is itself signed with the new key (keyid = the thumbprint inside the body), so the identity is bound to the key that consumed the token, in one atomic step. A captured enrollment request is useless: replaying it (same key) returns the same sensor, whose private key the attacker does not have; altering it breaks the signature. (A thief holding an *unused* token can of course enroll a key of their own: that is T1, bounded by single use, short expiry and approval.) Re-sending the same enrollment with the same key is idempotent (restart while pending does not burn another use). |
| E7 | **Rotation and revocation.** The SDK rotates its key every 30 days (configurable 1–90) with `POST /api/v2/sensor/keys {public_key}`, signed by the old key *and* carrying a proof by the new key; the old key stays valid for 10 minutes or until the new one is first used. The doorbell action `rotate_key` (RFC-023 K1) forces it. Revocation, quarantine, rejection and disable are checked **on every request** as they are today (§3.2: no cache, the sensor row is read per request), so revocation latency stays one request. If a cache is ever added in front of key lookup, it is invalidated in the same request as the write (the RFC-024 session pattern). |
| E8 | **Capabilities are claims, policy narrows.** The enrollment request carries the same report as the heartbeat (RFC-029 §4.3.1: tools + versions + installed, capabilities, max concurrency, os, arch) plus SDK, sensor and protocol versions, features and an optional image digest. Effective = reported ∩ the token's ceiling ∩ any later admin limit. The admin never has to type tools. |
| E9 | **Identity strength is shown and used, not assumed.** Each sensor gets an `assurance` level: `legacy_key` (bearer `rda_`), `key_bound` (E4/E5), `platform_attested` (enrolled through a verified Kubernetes / cloud / CI identity), later `hardware_attested`. Separately, **build provenance** is shown as a *claim*: the reported image digest matched against our cosign-signed releases (RFC-031 D11) is labelled "first-party build (reported)", never "verified". |
| E10 | **Secrets in jobs.** Scan credentials are released only to sensors that are approved, `key_bound` or higher, in the job's zone, and at or above the tenant's minimum assurance; they are **sealed per job to the sensor's X25519 encryption key with HPKE (RFC 9180)** and bound to the command id and expiry, so the commands table, logs, backups and any other sensor see only ciphertext. Legacy-key sensors never receive credentials (they keep sensor-local credentials, RFC-023 D12 T1). |
| E11 | **Keyless joins** for workloads that already have an identity: `kubernetes` (projected service-account token, audience `openctem`, verified against the cluster's OIDC JWKS or a pinned static JWKS for private clusters), `github` / `gitlab` (CI OIDC id tokens, for the CI-runner role: one ephemeral sensor per pipeline run), `aws` / `gcp` / `azure` (signed instance identity documents). Configured as **join rules** (issuer + claim matches → tenant, role, zone, tags, approval); no secret is stored anywhere. |
| E12 | **One identity per running instance.** Kubernetes replicas, autoscaled pods and CI jobs each enroll their own key; shared credentials across replicas are not supported in the new model. Instances can be `ephemeral` (from the token or join rule): removed automatically after 1 h offline, their history kept. |
| E13 | **Cloned-identity detection.** Every process start picks a random `instance_id` sent on hello/heartbeat. Two live `instance_id`s for one sensor within the heartbeat window means the key was copied: the sensor is flagged `identity_cloned`, alerted and (tenant policy, default on) quarantined. Applies to `rda_` sensors too, from Phase 0. |
| E14 | **Enrollment token handling on the host.** Accepted from a file (`--enroll-token-file`, Docker/Kubernetes secret) or the environment; after enrollment the SDK ignores it and logs a reminder to remove it. Because it is single-use and short-lived, exposure after use is harmless, unlike today's key. |
| E15 | **Outbox encryption stays decoupled from credentials.** It already is: a random local `outbox.key` (§3.5). The identity key lives beside it on the sensor's persisted storage, and neither is ever derived from the other or from a credential the platform issues, so rotation, re-enrollment and identity upgrade never strand queued results. |
| E16 | **Everything is audited** in the hash-chained audit log: token created / revoked / used / refused (exhausted, expired, wrong tenant), sensor enrolled, approved, rejected, key registered, rotated, revoked, identity upgraded from `rda_`, clone detected, credential sealed for a command. Signature failures are aggregated per sensor (one event per minute) to avoid log floods. |
| E17 | **Compatible by construction.** All protocol changes are additive v2 routes or optional request members (RFC-029 §4.11). `rda_` bearer keys keep working on v1 and v2 until the tenant opts into "require key-bound identity", and platform-wide at the protocol-v1 / `rda_` sunset (decision Q6). |

## 3. Current state (verified 2026-10-02, api `origin/develop` 0a45a752, sdk-go and sensor `origin/main`)

### 3.1 Creation and the key

- **Only an administrator creates a sensor.** `POST /api/v1/sensors`
  (`sensors:write`, owner/admin since migration 000246;
  `internal/infra/http/routes/scanning.go:267-303`) →
  `SensorHandler.Create` (`internal/infra/http/handler/sensor_handler.go:331`,
  tenant from the JWT at :343) → `SensorService.CreateSensor`
  (`internal/app/sensor/service.go:126-170`, audit `sensor.created` at :163).
  The request carries name, type, description, capabilities, tools,
  execution mode and max jobs (`sensor_handler.go:112-120`); **no zone**
  (assigned afterwards: `PUT /api/v1/scan-zones/{id}/sensors/{sensorId}`,
  `scanning.go:347-348`). The key is in the response once
  (`sensor_handler.go:311-315, 363-366`). There is no v2 management API.
- **Key:** `rda_` + hex(32 bytes `crypto/rand`) = 68 characters, 256 bits;
  `prefix = key[:12]` stored for display (`service.go:1071-1082`). No
  checksum, so a leaked key cannot be recognised offline as ours.
- **At rest:** HMAC-SHA256 with a pepper (`pkg/crypto/hash.go:77-84`); the
  pepper **is `APP_ENCRYPTION_KEY`** (`cmd/server/services.go:1311`), i.e.
  the encryption key doubles as the MAC key; with no pepper (dev) plain
  SHA-256 (`hash.go:42-46`). Columns `api_key_hash VARCHAR(64)` (unique
  index), `api_key_prefix VARCHAR(12)` (`migrations/000016_agents.up.sql:19-20,169-170`),
  `key_expires_at` (000185). Multi-key table `sensor_api_keys` (000016:65-80,
  renamed in 000230:73) with `scopes`, `expires_at`, `last_used_ip`,
  `use_count`, revocation.
- **Scopes exist but are not enforced**: `HasScope` has no caller outside
  `pkg/domain/sensor/api_key.go`; `service.go:776-777` calls enforcement
  "Phase 4" (RFC-014 Phase 4, still open).

### 3.2 Authentication

- `Authorization: Bearer <key>` or `X-API-Key`; query-string keys refused
  (`ingest_handler.go:1194-1213`). v1: `IngestHandler.AuthenticateSource`
  (`ingest_handler.go:390-428`) on the whole `/api/v1/agent` group
  (`scanning.go:248`). v2: `SensorResultsV2Handler.Authenticate`
  (`sensor_results_v2_handler.go:61-89`) on `/api/v2/sensor`
  (`sensor_v2.go:110`).
- Lookup (`service.go:831-882`): peppered hash (:839), then legacy plain
  SHA-256 (:843), then `sensor_api_keys` (:850, 906-941), each an equality
  match on a unique index. Tenant comes from the sensor row
  (`ingest_handler.go:419-421`), never from the request: correct.
- Status (`service.go:884-897`): `active` passes, `revoked` never,
  `disabled` passes only on heartbeat / hello as "paused". Expiry checked at
  :866. **No cache**: every request reads the database, so revoke, disable
  and delete take effect on the next request (`DisableSensor` /
  `RevokeSensor`, `service.go:970-1017`). Heartbeat, renewal and expiry
  writes are conditional on `status='active'`, so they cannot resurrect a
  revoked sensor (`sensor_repository.go:318-330, 428-447`).
- `last_seen` updated asynchronously (`service.go:873-878`); the client IP
  is recorded only on heartbeat (`sensor_control_v2_handler.go:209` →
  `service.go:472-484`); the multi-key path records usage with an **empty
  IP** (`service.go:936`).

### 3.3 Rotation, renewal, expiry

- Admin regenerate: `RegenerateAPIKey` (`service.go:570-602`): hard
  rotate, old key dead instantly, new key never expires, all
  `sensor_api_keys` rows revoked (:592).
- Self-renew: v1 `POST /api/v1/agent/renew` (`scanning.go:185`), v2
  `POST /api/v2/sensor/keys` (`sensor_v2.go:97`,
  `sensor_control_v2_handler.go:537`, 201 + `no-store`), rate-limited
  (burst 5, then 1 per 120 s, `scanning.go:25-28,167`), logic
  `RenewAPIKey` (`service.go:642-698`).
- **`SENSOR_KEY_TTL` defaults to 0: keys never expire**
  (`config.go:180-184, 809`). With a TTL, renewal adds an overlapping key
  row and the old inline key keeps `min(15 min, new expiry)`
  (`service.go:673-681, 714, 745-754`); the heartbeat rings `rotate_key`
  inside `SENSOR_KEY_RENEW_BEFORE` (`cmd/server/handlers.go:640-646`,
  `internal/app/sensor/doorbell.go:157-159`). Expiry is lazy (no expiry
  job); fleet health shows `key_expired` / `key_expiring`
  (`pkg/domain/sensor/fleet_health.go:54-55`); no notification is sent.
- *Since this was written:* renewal retires the key that was presented
  (inline or a key row) and every other key the sensor still held after
  `SENSOR_KEY_RENEW_GRACE` (default 15 min), so a renewal has one successor
  and a copied `rda_` key can no longer renew a parallel line of 90-day keys
  ([agent-identity.md](../architecture/agent-identity.md#renewal-retires-the-presented-key)).
  Before, the presented key stayed valid until its own expiry and only
  already-expired rows were pruned.
- **Auto-renewal is off on every install path.** The sensor renews only with
  `-key-autorenew` / `PLATFORM_KEY_AUTORENEW` (sensor `main.go:214,427`);
  the Helm chart defaults `keyAutoRenew: false` and documents why: the
  renewed key is written to `~/.openctem/sensor-credentials.json`
  (sdk-go `pkg/platform/credentials_file.go:15-68`; sensor
  `daemon_doorbell.go:56-122`), which **no snippet and no chart volume
  persists**, so a recreated container would start with the revoked key.
  Net effect today: every deployed key is a static, non-expiring bearer
  secret.

### 3.4 Bootstrap tokens and self-registration: dead code

- `ErrBootstrapToken*` (`pkg/domain/sensor/errors.go:79-95, 129-135`) are
  never referenced. `RegistrationToken` (`registration_token.go:10-143`)
  and its repository interface (`repository.go:269-293`) have no
  implementation and no wiring. The `registration_tokens` table
  (000016:85-103: `token_hash`, `max_uses` default 1, `expires_at`) was
  moved to the `deprecated` schema by 000213:26-27,42.
  `PlatformRegistrationRateLimiter` (`middleware/ratelimit.go:528-553`) is
  never constructed. (RFC-014 §Problem still describes registration tokens
  as live; that sentence is stale.)
- The SDK still has the client side: `platform.Bootstrapper.Register` posts
  a bootstrap token to `/api/v1/platform/register` (sdk-go
  `pkg/platform/bootstrap.go:124-227`). The API serves no such route
  (RFC-029 §3), so the chart's `mode: platform` (`BOOTSTRAP_TOKEN`) cannot
  register against an OpenCTEM API, as the chart's values comment says.
- Platform sensors (`is_platform_sensor`, no tenant) have no creation API
  (`SetPlatformSensor` has no caller); every v2 control route refuses them
  (`sensor_control_v2_handler.go:97-99`); `CanUsePlatformSensors` is
  always false in this build (`internal/app/adapters.go:127-128,186-187`).
  Out of scope here, as in RFC-029.

### 3.5 Binding, leak detection, secrets in jobs

- **Nothing binds a key to a host**: no per-sensor IP allow-list (the tenant
  IP allow-list explicitly exempts sensor keys,
  `middleware/ip_allowlist.go:23-28`), hostname is reported and overwritten
  on each heartbeat (`ingest_handler.go:223`), no mTLS, no request signing,
  no nonce. `Content-Digest` on v2 results is unkeyed integrity
  (`pkg/sensorproto/v2/digest.go:12`), not authentication.
- **Leak detection: none.** No new-IP or concurrent-host signal; per-request
  key use is not audited; `sensor.connected` is written only on an
  offline → online transition (`internal/app/audit/service.go:514-526`).
  The audit vocabulary covers created / updated / deleted / activated /
  deactivated / revoked / key_regenerated / key_renewed
  (`pkg/domain/audit/value_objects.go:130-142`).
- **Secrets can reach sensors in clear.** The platform does not release
  stored credentials into commands, but `scanner_config` is a user-supplied
  map passed through verbatim (`internal/app/scan/trigger.go:513-529`),
  screened only for dangerous keys (`internal/app/security_validator.go:213-235`),
  so auth headers or tokens typed into a scan config travel in the command
  and sit in the `commands` table. The per-command auth token
  (`pkg/domain/command/entity.go:339-361`) is never called.
- **Outbox encryption is already independent of the key:** AES-256-GCM with
  a random 32-byte `outbox.key` created 0600 next to the outbox (sdk-go
  `pkg/outbox/store.go:23-41, 264-328`; override `SENSOR_OUTBOX_KEY_FILE`).
  Key rotation or re-enrollment does not touch it. E15 keeps it that way;
  losing `outbox.key` quarantines pending items (`store.go:264-266`).

### 3.6 SDK and sensor

- sdk-go `main` = `v0.10.0` (`726b38b`): sends the key only as `Bearer`
  (`pkg/client/client.go:974`, `pkg/client/v2.go:683`); the HTTP transport
  has no client-certificate support and relies on the system trust store
  (`pkg/httpsec/ssrf.go:275-280`); SSRF-guarded dialer, redirects refused
  (`ssrf.go:245-274, 339, 352-360`). `KeyRenewManager` renews at half-life
  and persists through an `OnRotated` callback (`pkg/platform/keyrenew.go:21-55, 242-260`).
  Capability report: `BaseSensor.SetCapabilityReporter`
  (`pkg/core/base_sensor.go:85-103`), SDK and sensor build info on every
  heartbeat (`pkg/core/build_info.go:44,52`). **No RFC 9421, Ed25519 or
  DPoP code** exists. The `sensorkit` facade RFC-029 §8.3 plans is not on
  `main` yet; this RFC's SDK work lands in it.
- Sensor `main` (`0a535a5`): key from `-api-key`, `API_KEY` or the config
  file (`main.go:169,322,340-345`), no `*_FILE` variant; only the 12-char
  prefix is logged (`platform.go:112`, `daemon_doorbell.go:61-64`). Tools are
  probed with `<bin> --version` and cached 10 min
  (`capabilities.go:63-163`; sdk `pkg/core/exec.go:228-247`). Images are
  cosign keyless-signed (`.github/workflows/docker-publish.yml:205-271`),
  release checksums signed with `cosign sign-blob` (`.goreleaser.yaml:62-69`);
  **no SBOM or SLSA provenance** yet (`provenance: false`, `sbom: false`,
  `docker-publish.yml:154-155,178-179`).
- UI: `ui/src/features/sensors/components/install-sensor-dialog.tsx`,
  `sensor-install-flow.tsx`, `sensor-install-snippets.tsx` (passes the
  fresh key in `X-Sensor-API-Key` to `GET /sensors/{id}/config-templates`,
  :49-69), `regenerate-key-dialog.tsx`. Snippets
  (`internal/app/sensor/config_templates_builtin.go`): docker `-e API_KEY`
  + outbox volume, compose `.env`, Kubernetes Secret + `replicas: 1` +
  `Recreate` ("one sensor identity (one key)").
- Helm (`helm-charts` `main`, `charts/openctem/templates/sensor-deployment.yaml`):
  daemon mode reads `API_KEY` from a Secret; `replicas` is a value
  (default 1) with a comment, nothing stops N replicas sharing one key.

### 3.7 Summary of gaps

| # | Gap | Where |
|---|---|---|
| G1 | A human handles the long-lived credential (UI → clipboard → shell / `.env` / Secret / chat) | §3.1 |
| G2 | The credential is a bearer secret, never expires by default, is not auto-renewed on any install path | §3.3 |
| G3 | Nothing binds it to a host; no leak or clone detection; per-key IP not recorded | §3.5 |
| G4 | Enrollment tokens were designed (RFC-014, RFC-023 D10) and their remains are dead code; the chart's bootstrap mode targets a route that does not exist | §3.4 |
| G5 | The admin must type tools the platform cannot know (fixed for dispatch by RFC-029 §4.3.1, still asked in the create dialog) | §3.1 |
| G6 | One key can run N replicas | §3.6 |
| G7 | Secrets typed into scan configs travel in clear inside commands | §3.5 |
| G8 | Scopes on keys are not enforced (RFC-014 Phase 4) | §3.1 |
| G9 | The HMAC pepper is the data-encryption key (key reuse across purposes) | §3.1 |

## 4. Design principles for machine identity

Each principle below maps to the decisions that implement it.

| Principle | Taken here |
|---|---|
| **Enroll, don't pre-create.** A short-lived or use-limited *enrollment* secret, exchanged once for a per-machine identity; the machine registers itself with its own facts | E1, E2 |
| **Approval queue** for joins that are not pre-authorised; pre-approval as a token property (RFC-023 D10) | E3 |
| **Machine-generated key, private key never leaves the host** | E4 |
| **Proof of possession on every request**, not a bearer secret: RFC 9421, DPoP (RFC 9449), mTLS-bound tokens (RFC 8705) | E5 |
| **Short-lived, auto-rotated credentials; revocation by short TTL or per-request check** | E7 |
| **Keyless / delegated joining** with an identity the workload already has (cluster, CI and cloud OIDC or instance identity) | E11 |
| **Ephemeral identities** auto-removed when gone | E12 |
| **Tags / policy assigned by the enrollment credential**, not chosen by the joiner | E2 |
| **Claims from the machine are input, not authority**: a node's self-reported labels do not grant it rights | E8, E9 |

## 5. Threat model

Assets: the tenant's **scan targets and network map** (sent in jobs), **scan
credentials** (in some jobs), the **integrity of findings** (a sensor's
results change risk scores, auto-resolve findings), the platform's
availability, and other tenants' data.

### 5.1 Threats and controls

| # | Threat | Today | After this RFC | Residual |
|---|---|---|---|---|
| T1 | **Stolen enrollment token** (chat, ticket, shell history) | n/a; the equivalent is the sensor key itself, valid until regenerated | single-use tokens are dead after use; an unused one expires in ≤60 min; a reusable one needs approval by default, and every use shows up as a new pending sensor with a fingerprint the operator never saw | a thief who uses a *pre-approved reusable* token before expiry gets a sensor in that token's zone; bounded by the token's role/zone/tool ceiling, visible in the fleet list and audit, and the token can be revoked |
| T2 | **Stolen sensor credential copied to another host** | the `rda_` key works anywhere, from any IP, until an admin notices and regenerates; no signal | there is no credential on the wire to steal; the private key must be copied off the host (root or volume access). A copy running in parallel is detected (E13); a copy used after the original stops is indistinguishable, which is why rotation and attestation exist | an attacker with root on the sensor host *is* the sensor; that is true of every system in §4 without hardware keys (TPM, Phase 5) |
| T3 | **Captured request / log line replayed** | the bearer key in any captured header is the credential | a signature covers method, URI and body digest, expires within 300 s, and carries a nonce; v2 operations are idempotent by design (RFC-026 report ids, idempotent claims, RFC-029 §4.10), so even a replay inside the window changes nothing | none of practical value |
| T4 | **Malicious or compromised sensor claims tools to receive jobs** (exfiltrating targets, network maps, or credentials) | since RFC-029 §4.3.1 a sensor that reports a tool gets that tool's jobs (within admin limits and its zone) | the token's ceiling caps what it may claim; the zone caps which targets; approval gates any job; credentials go only to `key_bound`+ approved sensors at the tenant's minimum assurance, sealed per job (E10); a sensor that keeps claiming a tool and failing or returning nothing for it is flagged | a sensor that is *legitimately* approved for a zone sees that zone's targets: that is its job. Minimise blast radius with zones and narrow tokens |
| T5 | **Spoofed tool or build versions** | reduced to safe tokens (RFC-029 §4.3.1) and displayed as fact | reduced to safe tokens and shown as *reported*; the image digest is compared with signed releases but labelled a claim (E9); nothing authorises on a version | a lying sensor can look up to date; RFC-031's self-test and content reporting make this detectable, not impossible |
| T6 | **Malicious results** (poisoned findings, mass auto-resolve) | per-sensor key, server-stamped provenance (RFC-026) | unchanged, plus provenance carries the assurance level, and auto-resolve from a `legacy_key` sensor can be disabled by tenant policy | covered by RFC-026 §5 |
| T7 | **Compromised platform pushes to sensors** | unsigned jobs, unsigned commands | out of scope here, owned by RFC-023 P5/P6 (signed jobs, pinned root key) and RFC-031 D11/D12 (signed releases only). This RFC delivers what they need: the sensor pins the platform's job-signing root **at enrollment**, from the enroll response, which arrives over TLS verified against the CA fingerprint the install command carries (kubeadm's `--discovery-token-ca-cert-hash` idea) | a platform already compromised when the sensor enrolls can hand it a root of its own choosing; the operator can compare the root fingerprint the sensor logs with the one published for the installation |
| T8 | **Cross-tenant** (a token or sensor used to reach another tenant) | the tenant is derived from the key (correct) | tenant comes only from the token / join rule, never from the request; the enrollment lookup is by token id then constant-time hash compare; tokens, rules and keys are tenant-scoped rows; join rules are unique per (issuer, subject pattern) across tenants so one Kubernetes identity cannot match two tenants | — |
| T9 | **Enrollment endpoint abuse** (brute force, flooding pending queues) | n/a | unauthenticated route behind per-IP and per-token-id rate limits; uniform `401` problem for every token failure (no expired / exhausted / unknown distinction, CLAUDE.md rule 8); pending sensors per token capped (default 50) and auto-expired after 7 days unapproved | — |
| T10 | **Credential in env vars, process lists, logs, crash dumps** | the long-lived key lives in `API_KEY` env / Secret for the life of the sensor; snippet responses carry it | the only secret ever in the environment is the enrollment token, single-use; the identity key is a file read by the SDK; the SDK never logs the token or key (redaction test in the conformance suite) | `/proc/<pid>/environ` keeps the original environment even after `Unsetenv`; prefer the token file |
| T11 | **Revocation latency** | next request already (no cache, §3.2), but a leaked key is never revoked because nobody learns of the leak | next request (E7), and clone detection (E13) and leak scanning give the signal that triggers it | a sensor mid-scan finishes its scan; its results are refused on push |
| T12 | **Air-gapped / clock skew** | n/a | signatures need clocks within ±5 min; the server returns its time in a `clock-skew` problem so the SDK reports it in health instead of failing silently; skew limit configurable per installation | an installation with no time source must configure NTP or widen the window |
| T13 | **Downgrade** (an attacker forces bearer mode) | n/a | once a sensor has a registered key, the server refuses its bearer key; tenants can require key-bound identity for all sensors | before the tenant policy is on, a *never-upgraded* `rda_` sensor is exactly as safe as today |
| T14 | **Shared credential across replicas** | the chart can run N replicas with one key; one leak = all; no per-replica revoke; heartbeats of N processes overwrite each other | one identity per instance (E12); ephemeral cleanup | — |

### 5.2 Why request signatures and not mTLS as the default

mTLS is the textbook answer and stays available (Phase 5). It is not the
default for four reasons that are specific to how OpenCTEM is deployed:

1. **Corporate egress TLS inspection.** Sensors run inside customer networks;
   many enterprises force outbound HTTPS through an inspecting proxy that
   re-signs server certificates. A client certificate cannot pass through it
   (the proxy terminates the client's TLS). RFC 9421 signatures travel in
   headers and survive. The install snippets already handle the inspection
   case on the server-certificate side (`SENSOR_CA_CERT_FILE`).
2. **The built-in gateway and any customer load balancer terminate TLS**
   (`deploy/gateway/Caddyfile`). Caddy can require client certificates and
   forward them in a header, but the API must then trust a header from one
   hop, and every customer LB/WAF in front must pass the certificate through.
   That is a deployment burden on every installation for the default path.
3. RFC 9421 gives **per-message integrity** (body digest covered), which
   mTLS does not give past the terminating hop, and a signature in a log
   line is useless to a reader.
4. The profile is **already decided** (RFC-026 §4 iteration 2) and the
   results route is built for it.

DPoP (RFC 9449) solves the same problem for OAuth access tokens; with our
own protocol a token exchange adds a moving part without adding security
over signing every request with the same key.

## 6. Design

### 6.1 Flow

```
 Admin (UI)                     Platform (api)                         Sensor host
 ──────────                     ──────────────                         ───────────
 Add sensor: role, zone,
 tags, uses, expiry, approval
   ──POST /sensor-enrollment-tokens──►  store HMAC(token), policy
   ◄── command with ocse_… + CA fp ───
                                                                  first start:
                                                                  generate Ed25519 (+X25519)
                                                                  write identity/ 0600
                         ◄──── POST /api/v2/sensor/enroll ───────  body: token, public keys,
                               (RFC 9421-signed with the new key)   host facts, tool report
                         verify signature (key in body),
                         consume one use atomically,
                         create sensor (pending|approved),
                         register key, audit
                         ───► 201 {sensor_id, approval, key_id,
                                   job-signing root, intervals}
                                                                  log: "enrolled as <id>,
                                                                  key SHA256:ab12…, pending"
 Pending approval list ◄── (only when token says manual)
 compare fingerprint, Approve
                         ◄──── signed GET /hello, POST /heartbeat ─  (pending: 200, no jobs)
                         ───► approval: approved
                         ◄──── signed commands poll / results ─────  normal operation
                         ◄──── signed POST /keys {new public key} ─  every 30 days
```

### 6.2 Enrollment token

- Format (revised 2026-10-03, §10.4): `octe_` + base62(32 random bytes,
  43 characters) + base62(CRC32 of the random part, 6 characters), the same
  shape as an `octs_` sensor key. The token is looked up by its peppered
  hash, like a sensor key, so it needs no separate public id. (Originally
  proposed as `ocse_` + id + `_` + secret + CRC32.) The `octe_` prefix is
  distinct from `oct_` (which the gateway routes as user API keys), from
  `octs_` and from `rda_`. Proposed for GitHub secret scanning partner
  registration together with `octs_`, so leaked tokens and keys in public
  repositories are reported to us.
- Stored: `sensor_enrollment_tokens (id, tenant_id, secret_hash, name,
  role, zone_ids, tags, tool_ceiling, capability_ceiling, approval_mode,
  ephemeral, name_template, max_uses, use_count, expires_at, revoked_at,
  created_by, created_at, last_used_at)`. `secret_hash` = HMAC-SHA256 with
  the server pepper, compared in constant time.
- Defaults: `max_uses 1`, `expires_at now+60min`, `approval auto` when
  `max_uses = 1`, else `manual`. Reusable maximum 30 days (kept short because keyless joins exist for fleets).
- The token never appears in a URL. The UI shows it once, inside the
  rendered command, and lists the token afterwards by name and id only.

### 6.3 `POST /api/v2/sensor/enroll`

Unauthenticated route in the sensor group (allow-listed in
`route_authz_coverage_test` with the reason), rate-limited.

```json
{
  "enrollment": { "method": "token", "token": "ocse_…" },
  "keys": {
    "signing":    { "kty": "OKP", "crv": "Ed25519", "x": "…" },
    "encryption": { "kty": "OKP", "crv": "X25519",  "x": "…" }
  },
  "sensor": {
    "name": "dmz-scanner-01", "hostname": "scan01", "instance_id": "…",
    "os": "linux", "arch": "amd64",
    "sdk_version": "0.11.0", "sensor_version": "0.6.0", "protocol": 2,
    "features": ["signed_requests", "sealed_credentials", "signed_jobs", "zone_guard"],
    "image_digest": "sha256:…"
  },
  "report": { "tools": [ … ], "capabilities": [ … ], "max_concurrent_jobs": 5 }
}
```

- Signed with the new Ed25519 key; `keyid` = the RFC 7638 thumbprint of
  `keys.signing`. The server verifies the signature with the key from the
  body before touching the token (no oracle for unsigned guesses).
- Atomic consume: `UPDATE … SET use_count = use_count + 1 WHERE id = $1 AND
  revoked_at IS NULL AND expires_at > now() AND use_count < max_uses
  RETURNING …`, in the same transaction as the sensor insert and key insert.
- Idempotent: if a sensor already exists for (token id, key thumbprint) the
  same `201` body is returned and no use is consumed.
- Name: from the request (sanitised), else the token's template
  (`{hostname}`, `{role}-{n}`), uniquified within the tenant.
- `report` is processed exactly as the heartbeat report (RFC-029 §4.3.1),
  then capped by the token's ceilings.
- `201 {sensor_id, tenant_name, approval: "approved"|"pending", key_id,
  job_signing_root (when RFC-023 P6 ships), heartbeat_seconds}`; failures are
  RFC 9457 problems; every token failure is the same `401
  enrollment-refused`.

Keyless methods use the same route with `"method": "kubernetes" | "github" |
"gitlab" | "aws" | "gcp" | "azure"` and the platform-verifiable credential
instead of `token` (§6.8).

### 6.4 After enrollment

- **Authentication:** the v2 sensor group gains an RFC 9421 verifier in
  front of the existing sensor-key authenticator: a request with
  `Signature-Input` is verified (key by `keyid`, status check, `created` /
  `expires`, nonce `SET NX` in Redis with the window as TTL, digest match);
  a request with a bearer key goes through today's path *unless* the sensor
  has a registered signing key, in which case it is refused. If Redis is
  down, the nonce check degrades to a per-replica cache and logs it; the
  idempotency of v2 operations bounds the effect (T3).
- **Behind proxies.** `@target-uri` is the classic RFC 9421 pitfall behind
  a TLS-terminating gateway: the API rebuilds it from the installation's
  configured public sensor URL (`SENSOR_PUBLIC_API_URL`, else `APP_URL`),
  not from `X-Forwarded-*`, and the SDK signs the URL it dials, so both
  sides agree whatever sits in between. The built-in gateway already
  routes `/api/v2/sensor/*` to the API and must pass `Signature`,
  `Signature-Input` and `Content-Digest` unchanged (a smoke-test case in
  `deploy/gateway/smoke-test.sh`).
- **Pending sensors** get `hello` and `heartbeat` (so the admin sees them
  live and the report stays fresh); commands, content, suppressions,
  credentials, results and key rotation answer `403 pending-approval`.
- **v1 routes** stay bearer-only (frozen protocol). A key-bound sensor never
  calls v1; the SDK's v1 fallback (RFC-029 §6.1) is disabled once a key is
  registered.

### 6.5 Rotation, renewal, revocation

- `POST /api/v2/sensor/keys` (exists for `rda_` renewal) gains an optional
  body `{ "keys": {signing, encryption}, "proof": <JWS by the new key over
  sensor_id + new thumbprint + created> }`. Signed by the current key. The
  new key is active immediately; the old key is valid for 10 minutes or
  until the new key's first use, whichever is first. Empty body keeps the
  `rda_` renewal behaviour.
- **Identity upgrade** (existing sensors): a sensor authenticated with its
  `rda_` key calls the same endpoint with a body; the server registers the
  key, marks the sensor `key_bound`, and **retires the `rda_` key** after
  the same 10-minute grace. Nothing for the operator to do but upgrade the
  sensor image. The UI shows "Identity upgraded" in the sensor's history.
- **Expired while offline:** a key past its expiry may rotate within a
  7-day grace (signed by the expired key, the RFC-023 N-3 case); after
  that the sensor must re-enroll, which with a manual-approval policy needs
  the admin again.
- **Revocation** (revoke key, disable, quarantine, reject, delete): written
  to the database, which every request reads (§3.2); the next request from
  that sensor fails. The RFC 9421 verifier looks the key up by `keyid` the
  same way, so key-bound sensors keep one-request revocation.

### 6.6 Capabilities, assurance and credentials

- **Report:** unchanged semantics (RFC-029 §4.3.1), now also at
  enrollment, so a new sensor is dispatchable the moment it is approved.
- **Ceilings** from the enrollment token or join rule are stored on the
  sensor as its admin limits (`tools`, `capabilities`); the admin can
  narrow further in the sensor's page, never widen past what the sensor
  reports.
- **Assurance** (`legacy_key` < `key_bound` < `platform_attested` <
  `hardware_attested`) is a column computed from how the sensor enrolled
  and authenticates. Tenant policy: `min_assurance_for_jobs` (default
  `legacy_key`, i.e. no change) and `min_assurance_for_credentials`
  (default `key_bound`).
- **Build provenance (claim):** the reported `image_digest` is checked
  against the digests our release workflow signed (RFC-031 D11, read from
  the release metadata the platform already tracks for its release channel).
  Shown as "first-party build (reported)" or "unrecognised build". It never
  authorises anything; it helps an operator spot a sensor that is not what
  they deployed.
- **Credentials:** when a command needs a credential held by the platform
  (RFC-023 D12 T2), the dispatcher seals it with HPKE (RFC 9180,
  DHKEM(X25519) + HKDF-SHA256 + ChaCha20-Poly1305) to the claiming sensor's
  encryption key, with `info` = tenant, sensor id, command id and expiry,
  at **claim time** (so it is sealed to the sensor that actually claimed the
  command). The SDK opens it only inside the scan, never writes it to the
  outbox or logs. A `legacy_key` sensor is never sent one.

### 6.7 Sensor and SDK

- The SDK owns it all, in the `sensorkit` facade RFC-029 §8.3 plans (not
  on sdk-go `main` yet; until it lands, in `pkg/platform` next to
  `KeyRenewManager`), so "bump the SDK and done" holds: on start,
  load or create the identity in the state directory; if not enrolled and an
  enrollment token or join method is configured, enroll; if an `rda_` key is
  configured and no key is registered, upgrade; sign every request; rotate
  on schedule and on `rotate_key`; report `instance_id`. Sensor authors write
  no identity code.
- **Storage:** `/var/lib/openctem/state/identity/{signing.key,
  encryption.key,sensor.json}` (0600, directories 0700) on a persisted
  state volume that the snippets and chart add next to the outbox volume
  (`/var/lib/openctem/outbox`, already in every snippet); Phase 0 puts the
  renewed-key credentials file there too. A `KeyStore`
  interface lets a sensor supply a keystore (Kubernetes Secret, OS keyring,
  PKCS#11/TPM later).
- **Configuration:** `SENSOR_ENROLL_TOKEN` / `SENSOR_ENROLL_TOKEN_FILE`,
  `SENSOR_JOIN_METHOD` (`kubernetes`, `github`, …), `SENSOR_STATE_DIR`;
  `SENSOR_API_KEY` / `API_KEY` keep working (legacy, triggers upgrade).
- **Fingerprint on stdout:** `enrolled as <id> (tenant <name>), key
  SHA256:<thumbprint>, approval pending`, so the operator can match the UI.
- **Conformance suite** (RFC-023 D23) gains: signs correctly, refuses to
  send a bearer key after registration, never logs the token / key, handles
  `pending-approval`, rotates, reports clock skew.

### 6.8 Keyless joins (Phase 4)

Join rules per tenant: `sensor_join_rules (id, tenant_id, method, issuer,
audience, subject/claim matchers, jwks (static, optional), role, zone_ids,
tags, ceilings, approval_mode, ephemeral, max_active)`.

| Method | Credential the sensor presents | Platform verifies | Typical use |
|---|---|---|---|
| `kubernetes` | projected service-account token, `audience: openctem`, ≤1 h | signature via the cluster issuer's OIDC discovery JWKS, or a pinned static JWKS for private clusters; `iss`, `aud`, `exp`, `sub = system:serviceaccount:<ns>:<sa>`; pod binding claims | the Helm chart: no secret in values at all |
| `github` / `gitlab` | CI OIDC id token, `aud: openctem` | issuer JWKS; `repository`/`project_path`, `ref`, `job_workflow_ref`, environment | CI-runner role: one ephemeral sensor per pipeline run, removed when the run's token expires |
| `aws` / `gcp` / `azure` | signed instance identity document / identity token | provider signature, account / project / subscription, instance id, nonce | VM scanners in cloud accounts |

The keyless credential is used **once**, to enroll the key pair generated
in the same process; afterwards the sensor signs like any other. The
credential's `jti` is remembered until its `exp` to refuse reuse.

### 6.9 Kubernetes, multi-replica, air-gapped, outbox

- **Kubernetes.** Target: Deployment + `kubernetes` join method; each pod
  enrolls at start with its own key, `ephemeral: true` so replaced pods
  disappear from the fleet after 1 h offline. The outbox is per process
  (it is locked, RWO today), so replicas need per-pod storage either way:
  a StatefulSet with `volumeClaimTemplates` (state + outbox per pod; stable
  identity across restarts) is the chart's multi-replica shape; a
  Deployment with `emptyDir` is acceptable only for ephemeral workers whose
  undelivered results may be lost with the pod. Until Phase 4 the
  StatefulSet uses a reusable, pre-approved, ephemeral enrollment token
  from one Secret (one Secret, N identities). The chart's current
  shared-key mode stays for `rda_` installs only, single replica.
- **Air-gapped.** Token enrollment needs only sensor ↔ platform. Kubernetes
  joins use a pinned static JWKS. Cosign verification of builds is offline
  with the bundled trust root (RFC-031). Time sync is the one new
  requirement (T12).
- **Outbox.** Items written before an identity change must stay readable.
  They do: the outbox data key is already independent of the credential
  (§3.5, E15), and rotation or an `rda_` upgrade keeps the sensor id, so
  queued items deliver unchanged. Re-enrolling a host as a *new* sensor is
  different: items tied to commands the old identity claimed may be refused
  and land in the dead-letter folder, which the outbox health already
  surfaces. The SDK therefore drains the outbox before a voluntary
  re-enrollment.
- **Backup / restore of a sensor host** restores its identity: that is a
  feature (no re-enrollment) and the reason clone detection exists.

### 6.10 UI

- **Add sensor** dialog: role → zone (optional) → tags (optional) →
  "Restrict tools" (optional, collapsed) → uses and expiry (default "one
  sensor, 1 hour") → approval (default by uses) → **one command** per
  install type (docker, compose, Kubernetes, Helm, binary, CI). The command
  carries only the enrollment token, the URL and the CA fingerprint. Closing
  the dialog or going back loses nothing: no sensor exists yet.
- **"Waiting for sensor…"** in the dialog: it polls the token's use and
  shows the sensor as soon as it enrolls (name, host, key fingerprint,
  reported tools), so the operator sees success without leaving the dialog.
- **Enrollment tokens** list (Settings → Sensors): name, policy, uses,
  expiry, revoke.
- **Pending approval** tab with a badge: host facts, reported tools,
  fingerprint, source IP, token used; Approve / Reject (bulk). Needs
  `sensors:approve` (RFC-023 D16).
- **Sensor page → Identity panel:** method (token, kubernetes, …),
  assurance, key fingerprint, key age, last rotation, build provenance
  (reported), instance id, clone alerts; actions Rotate key, Revoke,
  Quarantine, Force re-enroll.
- Legacy sensors show a "Legacy key" badge with "upgrade the sensor to
  release with the new SDK to switch to key-bound identity automatically".
- **Join rules** (Phase 4) under Settings → Sensors → Join methods, with a
  copy-paste Helm values block and a GitHub Actions snippet.

## 7. Compatibility and migration

| What | Behaviour |
|---|---|
| Sensors with `rda_` keys, any SDK | unchanged on v1 and v2 (bearer) until the tenant requires key-bound identity or the platform sunset |
| Sensors upgraded to the new SDK with an `rda_` key | upgrade themselves (§6.5); the operator changes nothing; the stored `rda_` value becomes inert |
| Old SDK against a new platform | unaffected; the new routes and members are additive |
| New SDK against an old platform | `hello` does not advertise `signed_requests` → the SDK stays on the bearer key it was given; with only an enrollment token it reports "platform does not support enrollment" and exits non-zero (clear failure, no silent mode) |
| Install snippets | `GET /sensors/{id}/config-templates` keeps serving legacy snippets; a new `GET /sensor-enrollment-tokens/{id}/install` renders the enrollment snippets from the same templates directory |
| Management API | `POST /api/v1/sensors` keeps working (legacy key), marked deprecated in OpenAPI once enrollment ships |
| Sunset | tenant switch "require key-bound identity" first; platform-wide **90 days after Phases 1 and 2 ship** (§10.4, replacing 2027-04-01 in D3). `rda_` sensors that renew before then are already on `octs_` keys |

## 8. Implementation plan

Each row is one PR to `develop` (sdk-go/sensor: `main`), CI green and
verified end to end against a real sensor before the next depends on it.
Effort: S ≤ 1 day, M 2–4 days, L 1–2 weeks.

| Phase | Repo | Work | Effort | Risk |
|---|---|---|---|---|
| **0 — hardening now (no protocol change)** | api | `instance_id` on heartbeat + clone detection + alert (E13); record the client IP on every key use (today empty on the multi-key path) and audit "key used from a new IP"; key-expiry notification | M | low |
| | sensor + api snippets + helm | **make renewal survivable, then turn it on**: credentials file in the persisted state volume (`/var/lib/openctem/state`, next to the outbox) in every snippet and the chart; then default `SENSOR_KEY_TTL` (90 days, RFC-023 D10) and auto-renew on. Fixes G2 for every existing install without new protocol | S–M | medium: must ship snippets/chart before the TTL default, or recreated containers start with a revoked key (§3.3) |
| | api | separate HMAC pepper (`SENSOR_KEY_PEPPER`, derived with HKDF from `APP_ENCRYPTION_KEY` by default) with dual lookup during migration (G9); delete the dead bootstrap/registration-token code and fix or drop the chart's `mode: platform` (G4) | S | low |
| | api + ui | warn and mask when a scan's `scanner_config` contains credential-looking values (G7), until sealed credentials (Phase 3) give them a proper home | S | low |
| | api + ops | register `rda_` (and later `ocse_`) with GitHub secret scanning; add a checksum to newly issued `rda_` keys (old keys still accepted) | S | low |
| **1 — key-bound identity** | api | `sensor_keys` (public keys, thumbprint unique, alg, not_after, revoked_at); RFC 9421 verifier + nonce store in the v2 group; `POST /keys` with body (rotation + `rda_` upgrade); bearer refused once a key is registered; assurance column | L | high (auth path): DB round-trip tests, conformance vectors, fuzzing the signature-base builder |
| | sdk-go | identity store, signer (RFC 9421 + RFC 9530), automatic upgrade from `rda_`, rotation, `instance_id`; conformance additions | L | medium |
| | sensor | adopt; identity in the state volume; snippets unchanged | S | low |
| **2 — enrollment** | api | `sensor_enrollment_tokens`, management routes, `POST /api/v2/sensor/enroll`, approval state + `sensors:approve` permission (Go + seed migration + UI constants), pending gating, install renderer | L | medium |
| | ui | Add-sensor dialog rewrite, waiting panel, tokens list, Pending approval tab, Identity panel | L | low |
| | sdk-go + sensor + helm | enroll flow, token file, fingerprint log; chart: StatefulSet + token Secret mode | M | low |
| **3 — capability trust and sealed credentials** | api | token ceilings applied, assurance policy, build provenance check, HPKE sealing at claim, credential release only by policy | M–L | medium |
| | sdk-go | HPKE open inside the scan, never persisted | M | medium |
| **4 — keyless joins** | api + sdk-go + helm + ui | join rules; `kubernetes` (incl. static JWKS), `github`/`gitlab` (CI runner, ephemeral), then `aws`/`gcp`/`azure`; ephemeral GC; chart default becomes the Kubernetes join | L | medium |
| **5 — optional and retirement** | api + sdk-go + gateway | optional mTLS mode (gateway client-cert verification), TPM-backed keys, `hardware_attested`; tenant "require key-bound identity"; platform `rda_` sunset with v1 | M each | low |

Phases 1 and 2 ship in one SDK release if possible, so a sensor never sees
an enrollment flow that issues bearer keys. Phase 0 is independent and can
start now.

## 9. Alternatives considered

| Alternative | Why not (as the default) |
|---|---|
| Keep pre-creation, add tool auto-detection only | Fixes the tool list (already done by RFC-029 §4.3.1) but not the long-lived key passing through humans, or the shared key across replicas |
| Enrollment that issues an `rda_` bearer key (short TTL, auto-renew) | The UX win of E1 at low cost, but leaves a bearer secret on the wire and in logs. Acceptable only as a fallback if Phase 1 slips (Q4) |
| mTLS client certificates | §5.2: egress TLS inspection, TLS-terminating gateways and LBs. Kept as optional mode |
| Short-lived JWT access tokens + refresh (OAuth client credentials, `private_key_jwt`) | Bearer within its TTL; adds an issuer and a refresh path; signing each request with the same key is simpler and stronger |
| DPoP-bound access tokens (RFC 9449) | Equivalent security to E5 for our own protocol, with an extra token exchange |
| SPIFFE/SPIRE as a hard dependency | Excellent where it exists; too heavy to require for a sensor on one VM. Federation hook in Phase 5 (RFC-023 P3) |
| Trust tiers from self-reported build facts | A malicious host can report anything (E9); only attestation binds |

## 10. Decisions

| # | Question | Options | Recommended |
|---|---|---|---|
| Q1 | Default credential on the wire for v2 | (a) RFC 9421 signatures with a sensor-held Ed25519 key; (b) mTLS client certificates; (c) DPoP / short-lived JWTs | **(a)**, mTLS optional later (§5.2) |
| Q2 | Default approval | (a) single-use tokens auto-approve, reusable tokens need approval; (b) every enrollment needs approval; (c) never | **(a)**: one-shot install stays one step; fleets stay gated |
| Q3 | What happens to "create sensor + key" in the UI | (a) hidden behind "Legacy key" until sunset; (b) removed when enrollment ships; (c) kept as an equal option | **(a)** |
| Q4 | Order | (a) Phase 1 (key-bound identity) and Phase 2 (enrollment) in one SDK release; (b) enrollment first, issuing bearer keys, signatures later | **(a)**; (b) only if signatures slip past one release |
| Q5 | Scan credentials to sensors | (a) only to approved `key_bound`+ sensors, HPKE-sealed per job; legacy sensors use sensor-local credentials; (b) also to legacy sensors with a warning | **(a)** |
| Q6 | `rda_` retirement | (a) tenant opt-in "require key-bound identity" from Phase 1; new installs enrollment-only from Phase 2; platform-wide with the v1 sunset 2027-04-01; (b) keep `rda_` indefinitely | **(a)** |

### 10.1 Owner decisions (2026-10-02)

The owner accepted every recommendation in the table above.

| # | Decision | Consequence |
|---|---|---|
| D1 (Q1) | The default credential on the wire is a **sensor-held Ed25519 key with RFC 9421 request signatures**. mTLS client certificates are an optional later mode (Phase 5), never the default. | E4, E5 and §5.2 stand as written. Phase 1 builds the verifier and the signer; no bearer-token exchange (DPoP, JWT) is built. |
| D2 (Q2) | **Single-use enrollment tokens auto-approve; reusable tokens require approval.** | The E3 defaults stand: `approval auto` when `max_uses = 1`, else `manual`. |
| D3 (Q3, Q4, Q6) | The "create sensor + `rda_` key" flow stays only behind **"Legacy key"** in the UI. **Phases 1 and 2 ship in one SDK release**, so a sensor never sees an enrollment that issues bearer keys. **New installs are enrollment-only from Phase 2.** ~~`rda_` keys are retired platform-wide on 2027-04-01 together with protocol v1~~ **(superseded 2026-10-03, §10.4: `rda_` keys are retired 90 days after Phases 1 and 2 ship)**; a tenant can opt in earlier with "require key-bound identity". | The §7 sunset row follows §10.4. Until Phase 2 ships the legacy flow is the only flow, and Phase 0 hardens it. |
| D4 | **Start Phase 0 now**, independently of Phases 1 and 2. | Phase 0 is tracked in §10.2. |
| D5 (Q5) | **Scan credentials go only to approved, key-bound (or stronger) sensors**, HPKE-sealed per job. Legacy-key sensors keep sensor-local credentials. | E10 stands. Until Phase 3, Phase 0 warns when a scan's `scanner_config` looks like it carries a secret (G7). |

### 10.2 Phase 0 tracking

| Item | Where | Notes |
|---|---|---|
| Cloned-identity signal (E13 for `rda_` sensors) | api + sdk-go | The SDK sends a random per-process `instance_id` on every heartbeat (an optional member; older platforms ignore it). A restart replaces the instance once; when replaced instances come back 3 times within 15 minutes the sensor is flagged (`identity_cloned_at`, health reason `identity_cloned`, a timeline event) and `sensor.identity_cloned` (severity high) is written to the audit log once. Older SDKs are observed by hostname. Regenerating the key clears the flag. Quarantine waits for Phase 1. |
| Source IP on every key use | api | The inline key (`sensors.api_key_last_used_ip/_at`) and `sensor_api_keys` both record the last-used address from the trusted-proxy-aware client IP; a key used from another address than the previous request writes `key_ip_changed` on the sensor's activity timeline (folded and capped like every event, so a NAT pool cannot flood it; the audit log stays for administrator actions and the clone flag). |
| Renewal that survives a restart, then expiry by default | sdk-go, sensor, api snippets, helm | The SDK persists the renewed key in the state directory (`/var/lib/openctem/state`, 0600, atomic write) and prefers it over the configured key on start; every snippet and the chart mount that directory. Auto-renew is on in the sensor exactly when the state directory survives the container being recreated (a mounted, non-tmpfs volume; the chart decides explicitly because an `emptyDir` looks like a volume). The snippets and the chart also mount a separate content volume (`/var/lib/openctem/content`, the scanner content cache). **Only after that ships** does the API default change (#711): `SENSOR_KEY_TTL=2160h` (90 days), `rotate_key` rung at half-life (45 days before expiry). Only renewal applies the TTL: keys issued by an administrator keep no expiry until their sensor renews (a renewing sensor does on its first start), and a sensor that does not renew is never locked out. `rotate_key` is not rung for keys without an expiry: sensors that cannot renew would log it on every heartbeat. |
| Dedicated key-hash pepper (G9) | api | `SENSOR_KEY_PEPPER`; when unset it is derived with HKDF-SHA256 from `APP_ENCRYPTION_KEY`, so the MAC key is never the encryption key. Hashes made with the old pepper keep verifying (dual lookup; also the derived pepper once `SENSOR_KEY_PEPPER` is set, and `SENSOR_KEY_PEPPER_PREVIOUS` for replacing an explicit one); new, regenerated and renewed keys are stored with the new pepper. Rolling the API back below this release makes keys issued after it unknown to the older server. The `oct_` user API keys and SCIM tokens still use `APP_ENCRYPTION_KEY` as their pepper (follow-up). |
| Dead bootstrap and registration-token code (G4) | api, helm, sdk-go | Removed from the api and the chart (`mode: platform`) after a cross-repository search. In sdk-go the client is public API, so it is marked `Deprecated` rather than deleted (the SDK compatibility check allows additions only); it goes with the v1 sunset. |
| Secret-looking `scanner_config` values (G7) | api + ui | A warning in the save response and a hint in the form; never blocks. The warned values are masked (`********`) for callers without `scans:write` on scan reads, scan export and command payloads; editors, owners and admins see them, sensors receive them, and saving the mask back keeps the stored value ([sensors.md](../architecture/sensors.md)). |
| `rda_` in GitHub secret scanning | owner | Needs the GitHub partner program; steps in §10.3. |

### 10.3 Follow-up for the owner: GitHub secret scanning for `rda_` (and `ocse_`)

> Superseded in part by §10.4: the patterns to register are now `octs_` and
> `octe_` (checksummed), with `rda_` as the legacy pattern. The current
> patterns are in [agent-identity.md, *Credential formats*](../architecture/agent-identity.md#credential-formats).

Having GitHub report leaked keys in public repositories to us is done
through the **GitHub secret scanning partner program**, not a repository
setting, so it cannot be done from code.

What the program asks for (partner program page, linked in §11):

1. **A distinctive, high-entropy format.** `rda_` + 64 hex characters
   qualifies (unique prefix, 256 bits). A checksum suffix is strongly
   preferred because it lets GitHub, and us, reject false positives
   offline. Phase 0 does not change the `rda_` format, so `ocse_` (which
   carries a CRC32, E2) is the better first candidate; `rda_` can be
   registered alongside with the plain pattern.
2. **A public alert endpoint** run by the vendor (for example
   `https://openctem.io/.well-known/secret-scanning`, outside any tenant
   installation) that accepts `POST` with a JSON array of
   `{token, type, url, source}`, verifies the request signature (headers
   `Github-Public-Key-Identifier` and `Github-Public-Key-Signature`, ECDSA
   P-256 with SHA-256, against the keys published at
   `https://api.github.com/meta/public_keys/secret_scanning`) and answers
   quickly. OpenCTEM is self-hosted, so that endpoint cannot revoke a key
   itself: it can only record the report and, later, let an installation
   that opts in ask "was one of my keys reported" by hash prefix. That
   limits what registration buys us; decide this before applying.
3. **An optional validity check** (GitHub asks whether a reported token is
   live): not possible for a self-hosted product without phoning home, so
   the answer would be "unknown".
4. **Contact GitHub** through the partner program page to start
   onboarding, with the secret type names (`openctem_sensor_key`,
   `openctem_enrollment_token`), the regular expressions, the endpoint URL
   and a security contact.

**Until then, an organization can scan its own repositories for leaked
sensor keys with a custom pattern** (GitHub Advanced Security:
organization or repository *Settings → Code security → Secret scanning →
Custom patterns → New pattern*; enable push protection for it):

| Field | Value |
|---|---|
| Pattern name | `OpenCTEM sensor key` |
| Secret format | `rda_[0-9a-f]{64}` |
| Before secret | `(?:\A|[^0-9A-Za-z_])` |
| After secret | `(?:\z|[^0-9A-Za-z_])` |
| Test string | `API_KEY=rda_` followed by 64 hex characters |

The same expression works elsewhere:

```toml
# gitleaks (.gitleaks.toml)
[[rules]]
id = "openctem-sensor-key"
description = "OpenCTEM sensor key"
regex = '''\brda_[0-9a-f]{64}\b'''
keywords = ["rda_"]
```

### 10.4 Revision 2026-10-03: credential prefixes and the `rda_` sunset

Owner decisions (2026-10-03):

| # | Decision | Consequence |
|---|---|---|
| D6 | **New sensor API keys use `octs_`; enrollment tokens use `octe_`.** Both are `<prefix>` + base62 of 32 random bytes (43 characters, zero-padded) + base62 of the CRC32 of the random part (6 characters); the checksum lets secret scanners validate a token offline. | Implemented in `pkg/sensorkey`. Create, regenerate, renew and `RotateKey` issue `octs_` keys. The API rejects an `octs_` key whose checksum fails, and any `octe_` token presented as a key, before the hash lookup. The display prefix is 10 characters (`octs_` + 5). The checksum is a typo and scanner aid, **not** a security control. |
| D7 | **No sensor prefix starts with `oct_`**, which the HTTP layer routes to user / MCP API-key authentication. | A test pins that `octs_`, `octe_` and `rda_` bearer tokens never reach user-key authentication. |
| D8 | **`rda_` keys keep working until 90 days after enrollment (Phase 2) and Ed25519 key-bound identity (Phase 1) ship**; this replaces 2027-04-01 in D3. Live sensors move to `octs_` automatically on their next key renewal. | `Sensor.IsLegacyKey()`, `legacy_key` in the sensor response with a "legacy key" tag on the Sensors page, the `openctem_sensor_legacy_keys` gauge, and `previous_key_format` / `upgraded_from_legacy_key` in the `sensor.key_renewed` audit event. |
| D9 | Secret-scanning rules for `octs_`, `octe_` and legacy `rda_` ship in the repository's `.betterleaks.toml` and are documented for customers. | [agent-identity.md, *Credential formats*](../architecture/agent-identity.md#credential-formats). |

The SDK and the sensor never checked the `rda_` prefix (only test fixtures and
a log-redaction comment mention it), so no SDK or sensor release is needed for
`octs_` keys.

### 10.5 TODO (not before 2027-01-03): remove bearer credential storage

Key-bound identity (RFC-052) merged on 2026-10-05 (#1189), so the D8 sunset
falls **no earlier than 2027-01-03**, and only if enrollment / pairing
(Phase 2, RFC-052) has shipped by then; otherwise 90 days after it ships.
RFC-052 D-4 lets existing organizations keep `octs_` bearer keys, so the
storage can go only once **no** bearer key (`rda_` or `octs_`) is in use, not
merely when `rda_` is retired.

At that point, in one PR (code and migration together):

- drop `sensor_api_keys` (the bearer-key rotation store) and, on `sensors`,
  `api_key_hash`, `api_key_prefix`, `key_expires_at`, `key_pepper_id`,
  `api_key_last_used_at`, `api_key_last_used_ip` with their indexes; keep
  `auth_kind` (every row is `key_bound` afterwards);
- remove bearer authentication from the v2 sensor plane, the key
  create / regenerate / renew / rotate paths, the bearer entries of the token
  pepper and rekey registries, and the legacy-key UI;
- the up migration starts with a guard that **aborts** while any non-revoked
  sensor has `auth_kind = 'bearer'` or an active `sensor_api_keys` row, so a
  premature deploy cannot lock out a live sensor; the down migration recreates
  the empty table and columns (no bearer key works after a down).

State on the production restore of 2026-10-05: 8 sensors, all `bearer`
(7 active, 1 disabled); `sensor_api_keys` 2 rows, both active and used in the
last 7 days. Every one of them has to be re-paired or revoked first.

## 11. Sources

Platforms and projects we integrate with (checked 2026-10-02):

- GitHub Actions OIDC: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- Kubernetes bootstrap tokens: https://kubernetes.io/docs/reference/access-authn-authz/bootstrap-tokens/ ; kubelet TLS bootstrapping: https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/ ; projected tokens: https://kubernetes.io/docs/concepts/storage/projected-volumes/ ; bound tokens: https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/ ; issuer discovery: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
- SPIRE server (attestors, TTLs): https://spiffe.io/docs/latest/deploying/spire_server/ ; concepts: https://spiffe.io/docs/latest/spire-about/spire-concepts/
- Sigstore cosign verification: https://docs.sigstore.dev/cosign/verifying/verify/ ; SLSA provenance: https://slsa.dev/spec/v1.0/provenance

Standards:

- RFC 9421 HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421.html
- RFC 9530 Digest Fields: https://www.rfc-editor.org/rfc/rfc9530.html
- RFC 9449 DPoP: https://www.rfc-editor.org/rfc/rfc9449.html
- RFC 8705 OAuth mTLS and certificate-bound tokens: https://www.rfc-editor.org/rfc/rfc8705.html
- RFC 7523 JWT client authentication: https://www.rfc-editor.org/rfc/rfc7523.html
- RFC 7517 JWK, RFC 8037 (OKP / Ed25519 in JOSE), RFC 7638 JWK thumbprint: https://www.rfc-editor.org/rfc/rfc7638.html
- RFC 9180 HPKE: https://www.rfc-editor.org/rfc/rfc9180.html
- RFC 9334 RATS architecture: https://www.rfc-editor.org/rfc/rfc9334.html
- RFC 9457 Problem Details: https://www.rfc-editor.org/rfc/rfc9457.html
- IETF WIMSE architecture (draft): https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch-04
- GitHub secret scanning partner program: https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partnership-program/secret-scanning-partner-program
