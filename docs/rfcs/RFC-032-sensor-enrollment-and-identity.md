# RFC-032 — Sensor enrollment, identity and declared capabilities

> Status: **Proposed** (2026-10-02). Docs only; no code in this change.
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
| E2 | **Enrollment token** `ocse_<id>_<secret>`: 128-bit id for lookup, 256-bit secret, CRC32 checksum suffix (leak scanners can validate it offline), stored as HMAC-SHA256 with the sensor-credential pepper (as `rda_` keys are; Phase 0 stops reusing `APP_ENCRYPTION_KEY` as that pepper, §3.1 G9). The `id_secret` shape is the Kubernetes bootstrap-token shape (public id + secret). Policy on the token: tenant, role, zone(s), tags, tool/capability ceiling, `max_uses` (default 1), `expires_at` (default 60 min, max 30 days for reusable), approval mode, `ephemeral`, name template. Revocable; every use is audited. |
| E3 | **Approval:** single-use tokens default to **auto-approve** (creating the token *was* the human decision and it expires within the hour, as a GitHub runner registration token). Reusable tokens default to **manual approval**: the sensor appears as *Pending approval* with hostname, IP, OS/arch, versions, reported tools and its **key fingerprint**, which the sensor also prints in its log, so the admin can compare (SSH / Teleport style). A pending sensor can heartbeat but receives no jobs, content, credentials or configuration. |
| E4 | **Sensor identity = an Ed25519 key pair generated by the sensor**, stored 0600 in the sensor's persisted state volume (`/var/lib/openctem/state/identity/`), or supplied by a mounted file / Kubernetes Secret / OS keystore; TPM-backed keys later. Only the public key (JWK, RFC 7517/8037) and its thumbprint (RFC 7638) are sent. |
| E5 | **Every v2 request is signed** per the RFC-026 §4 iteration-2 profile (RFC 9421, `alg="ed25519"`, `keyid` = key thumbprint, `created`, `expires` ≤ 300 s, `nonce`, covered `@method @target-uri content-type content-digest`). No bearer secret is presented once a key is registered; the server refuses the `rda_` key for that sensor afterwards. Chosen over mTLS as the default because it survives TLS-terminating gateways, load balancers and **corporate egress TLS inspection**, which breaks client certificates (§5.2). mTLS stays an optional high-assurance mode (Phase 5). |
| E6 | **Proof of possession at enrollment.** `POST /api/v2/sensor/enroll` is itself signed with the new key (keyid = the thumbprint inside the body), so the identity is bound to the key that consumed the token, in one atomic step. A captured enrollment request is useless: replaying it (same key) returns the same sensor, whose private key the attacker does not have; altering it breaks the signature. (A thief holding an *unused* token can of course enroll a key of their own: that is T1, bounded by single use, short expiry and approval.) Re-sending the same enrollment with the same key is idempotent (restart while pending does not burn another use). |
| E7 | **Rotation and revocation.** The SDK rotates its key every 30 days (configurable 1–90) with `POST /api/v2/sensor/keys {public_key}`, signed by the old key *and* carrying a proof by the new key; the old key stays valid for 10 minutes or until the new one is first used. The doorbell action `rotate_key` (RFC-023 K1) forces it. Revocation, quarantine, rejection and disable are checked **on every request** as they are today (§3.2: no cache, the sensor row is read per request), so revocation latency stays one request. If a cache is ever added in front of key lookup, it is invalidated in the same request as the write (the RFC-024 session pattern). |
| E8 | **Capabilities are claims, policy narrows.** The enrollment request carries the same report as the heartbeat (RFC-029 §4.3.1: tools + versions + installed, capabilities, max concurrency, os, arch) plus SDK, sensor and protocol versions, features and an optional image digest. Effective = reported ∩ the token's ceiling ∩ any later admin limit. The admin never has to type tools. |
| E9 | **Identity strength is shown and used, not assumed.** Each sensor gets an `assurance` level: `legacy_key` (bearer `rda_`), `key_bound` (E4/E5), `platform_attested` (enrolled through a verified Kubernetes / cloud / CI identity), later `hardware_attested`. Separately, **build provenance** is shown as a *claim*: the reported image digest matched against our cosign-signed releases (RFC-031 D11) is labelled "first-party build (reported)", never "verified". |
| E10 | **Secrets in jobs.** Scan credentials are released only to sensors that are approved, `key_bound` or higher, in the job's zone, and at or above the tenant's minimum assurance; they are **sealed per job to the sensor's X25519 encryption key with HPKE (RFC 9180)** and bound to the command id and expiry, so the commands table, logs, backups and any other sensor see only ciphertext. Legacy-key sensors never receive credentials (they keep sensor-local credentials, RFC-023 D12 T1). |
| E11 | **Keyless joins** (Teleport-style join methods) for workloads that already have an identity: `kubernetes` (projected service-account token, audience `openctem`, verified against the cluster's OIDC JWKS or a pinned static JWKS for private clusters), `github` / `gitlab` (CI OIDC id tokens, for the CI-runner role: one ephemeral sensor per pipeline run), `aws` / `gcp` / `azure` (signed instance identity documents). Configured as **join rules** (issuer + claim matches → tenant, role, zone, tags, approval); no secret is stored anywhere. |
| E12 | **One identity per running instance.** Kubernetes replicas, autoscaled pods and CI jobs each enroll their own key; shared credentials across replicas are not supported in the new model. Instances can be `ephemeral` (from the token or join rule): removed automatically after 1 h offline, their history kept. |
| E13 | **Cloned-identity detection.** Every process start picks a random `instance_id` sent on hello/heartbeat. Two live `instance_id`s for one sensor within the heartbeat window means the key was copied: the sensor is flagged `identity_cloned`, alerted and (tenant policy, default on) quarantined. Applies to `rda_` sensors too, from Phase 0. Teleport's `bound_keypair` join does the same with a join-state generation counter. |
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

## 4. What the industry does

Only what informed a decision. All links are the vendors' own documentation.

| System | Enrollment credential | Machine credential | Rotation / revocation | What we take |
|---|---|---|---|---|
| **GitHub Actions self-hosted runners** | registration token, expires after 1 h, passed to `config.sh --token`; or a JIT config (`generate-jitconfig`) for one ephemeral runner | the runner generates a 2048-bit RSA key locally (file mode 600) and authenticates with it to get short-lived OAuth tokens | `--ephemeral` de-registers after one job | short-lived enrollment, host-generated key, ephemeral runners |
| **GitHub Actions OIDC** | — | per-job OIDC token from `token.actions.githubusercontent.com` with `sub`, `repository`, `ref`, `job_workflow_ref` claims, audience chosen by the job | valid for a single job | keyless CI joins (E11) |
| **Tailscale** | auth keys: one-off or reusable, ephemeral, pre-approved, tagged; 1–90 days (default 90); workload identity federation exchanges a cloud/GitHub OIDC token instead of a stored key | per-node key | node key expiry 1–180 days (default 180); revoking an auth key does **not** remove nodes joined with it; device approval queue; Tailnet Lock lets trusted nodes, not the server, sign new node keys | token properties (E2), approval (E3), ephemeral (E12) |
| **Teleport** | secret-based (`token`, default TTL 30 min; static tokens "strongly discouraged") or delegated join methods: ec2, iam, azure, gcp, github, gitlab, circleci, kubernetes, tpm; `bound_keypair` (client-generated key registered up front) recommended over secret-based | short-lived certificates (tbot default 1 h, max 24 h, renewed every 20 min) | `bound_keypair` keeps a join-state generation counter and **locks the bot when counters disagree, i.e. a cloned keypair** | join methods (E11), clone detection (E13) |
| **Kubernetes kubelet** | bootstrap token `[a-z0-9]{6}.[a-z0-9]{16}` (public id + secret), with expiry, cleaned by `tokencleaner`; `kubeadm token create` default TTL 24 h | kubelet submits a CSR; `csrapproving` auto-approves client CSRs by RBAC, never serving certs | `rotateCertificates` | `id.secret` token shape (E2), approval by policy (E3) |
| **Kubernetes service accounts** | — | projected token: audience-bound, default 1 h (min 600 s), bound to the pod's UID, refreshed at 80 % of lifetime; issuer discovery serves `/.well-known/openid-configuration` + JWKS | invalid once the pod is gone | the `kubernetes` join method (E11) |
| **SPIFFE / SPIRE** | node attestors: `join_token` (single-use), `aws_iid`, `azure_msi`, `gcp_iit`, `k8s_psat`, `tpm_devid`, `x509pop`, `sshpop` | X.509-SVID, default TTL 1 h | automatic | attestation-based identity; federation hook later |
| **Vault AppRole / Nomad** | `role_id` + `secret_id` (num-uses, TTL, `secret_id_bound_cidrs`); response wrapping delivers a secret in a single-use wrapping token, so interception is detectable | Vault token (CIDR-bindable); Nomad signs a per-task workload-identity JWT | `secret-id/destroy` | single-use delivery, CIDR binding as an optional extra |
| **Elastic Fleet** | enrollment token **per agent policy** | after enrollment, Fleet Server issues the agent its own least-privilege API key | revoking an enrollment token leaves enrolled agents working; unenroll invalidates the agent's key | policy-scoped tokens (E2) |
| **Tenable** | one linking key per instance for all sensor types; `nessuscli agent link --key --groups --ca-path` | after linking, the sensor uses unique credentials | regenerating the linking key does not affect linked sensors | link-then-own-credential; groups at link time; CA pin in the command |
| **CrowdStrike Falcon** | customer ID (CID) plus an optional provisioning token | per-sensor | — | the CID alone is not a secret; the provisioning token is the gate |
| **Datadog** | org API key | agent pulls Remote Configuration, which is signed and validated by the agent (Uptane/TUF in the agent source) | — | signed control-plane messages (RFC-023 P5/P6) |
| **Wiz sensor** | Helm chart takes a service-account client id + token | — | — | the shared-credential model this RFC moves away from |

Unverified (vendor docs behind a login or silent): the exact GitHub runner
token exchange, the GitHub OIDC token TTL, whether CrowdStrike can make
the provisioning token mandatory tenant-wide, Wiz Outpost/Broker auth.
None of them changes a decision.

### 4.1 Patterns extracted

| Pattern | Who | Taken here |
|---|---|---|
| **Enroll, don't pre-create.** A short-lived or use-limited *enrollment* secret, exchanged once for a per-machine identity; the machine registers itself with its own facts | GitHub runners, Elastic Fleet, Tailscale, Teleport, kubelet bootstrap, Tenable linking key | E1, E2 |
| **Approval queue** for joins that are not pre-authorised; pre-approval as a token property | Tailscale device approval / pre-approved keys, kubelet CSR approval, RFC-023 D10 | E3 |
| **Machine-generated key, private key never leaves the host** | GitHub runner (RSA key generated at config time, mode 600), kubelet (CSR), SPIRE, Tailscale node key | E4 |
| **Proof of possession on every request**, not a bearer secret | RFC 9421, DPoP (RFC 9449), mTLS-bound tokens (RFC 8705), Elastic Fleet / Datadog signed messages | E5 |
| **Short-lived, auto-rotated credentials; revocation by short TTL or per-request check** | kubelet rotation, SPIFFE SVIDs (~1 h), Teleport certs, Tailscale node-key expiry | E7 |
| **Keyless / delegated joining** with an identity the workload already has | Teleport join methods, SPIRE node attestors, Vault/Nomad workload identity, GitHub OIDC federation | E11 |
| **Ephemeral identities** auto-removed when gone | GitHub `--ephemeral` / JIT runners, Tailscale ephemeral nodes | E12 |
| **Tags / policy assigned by the enrollment credential**, not chosen by the joiner | Tailscale tagged keys, Elastic Fleet policy-scoped tokens, Tenable agent groups, Teleport token roles | E2 |
| **Claims from the machine are input, not authority** | every one of the above: a node's labels do not grant it rights (kubelet `NodeRestriction`) | E8, E9 |

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

- Format `ocse_` + base62(16-byte id) + `_` + base62(32-byte secret) +
  base62(CRC32). The `ocse_` prefix is distinct from `oct_` (which the
  gateway routes as user API keys) and from `rda_`. Proposed for GitHub
  secret scanning partner registration together with `rda_`, so leaked
  tokens and keys in public repositories are reported to us.
- Stored: `sensor_enrollment_tokens (id, tenant_id, secret_hash, name,
  role, zone_ids, tags, tool_ceiling, capability_ceiling, approval_mode,
  ephemeral, name_template, max_uses, use_count, expires_at, revoked_at,
  created_by, created_at, last_used_at)`. `secret_hash` = HMAC-SHA256 with
  the server pepper, compared in constant time.
- Defaults: `max_uses 1`, `expires_at now+60min`, `approval auto` when
  `max_uses = 1`, else `manual`. Reusable maximum 30 days (Tailscale's
  maximum is 90; ours is shorter because keyless joins exist for fleets).
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
| `kubernetes` | projected service-account token, `audience: openctem`, ≤1 h | signature via the cluster issuer's OIDC discovery JWKS, or a pinned static JWKS for private clusters (Teleport's approach); `iss`, `aud`, `exp`, `sub = system:serviceaccount:<ns>:<sa>`; pod binding claims | the Helm chart: no secret in values at all |
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
| Sunset | tenant switch "require key-bound identity" first; platform-wide on the protocol-v1 sunset (Q6) |

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
| mTLS client certificates (kubelet style) | §5.2: egress TLS inspection, TLS-terminating gateways and LBs. Kept as optional mode |
| Short-lived JWT access tokens + refresh (OAuth client credentials, `private_key_jwt`) | Bearer within its TTL; adds an issuer and a refresh path; signing each request with the same key is simpler and stronger |
| DPoP-bound access tokens (RFC 9449) | Equivalent security to E5 for our own protocol, with an extra token exchange |
| SPIFFE/SPIRE as a hard dependency | Excellent where it exists; too heavy to require for a sensor on one VM. Federation hook in Phase 5 (RFC-023 P3) |
| Trust tiers from self-reported build facts | A malicious host can report anything (E9); only attestation binds |

## 10. Decisions needed from the owner

| # | Question | Options | Recommended |
|---|---|---|---|
| Q1 | Default credential on the wire for v2 | (a) RFC 9421 signatures with a sensor-held Ed25519 key; (b) mTLS client certificates; (c) DPoP / short-lived JWTs | **(a)**, mTLS optional later (§5.2) |
| Q2 | Default approval | (a) single-use tokens auto-approve, reusable tokens need approval; (b) every enrollment needs approval; (c) never | **(a)**: one-shot install stays one step; fleets stay gated |
| Q3 | What happens to "create sensor + key" in the UI | (a) hidden behind "Legacy key" until sunset; (b) removed when enrollment ships; (c) kept as an equal option | **(a)** |
| Q4 | Order | (a) Phase 1 (key-bound identity) and Phase 2 (enrollment) in one SDK release; (b) enrollment first, issuing bearer keys, signatures later | **(a)**; (b) only if signatures slip past one release |
| Q5 | Scan credentials to sensors | (a) only to approved `key_bound`+ sensors, HPKE-sealed per job; legacy sensors use sensor-local credentials; (b) also to legacy sensors with a warning | **(a)** |
| Q6 | `rda_` retirement | (a) tenant opt-in "require key-bound identity" from Phase 1; new installs enrollment-only from Phase 2; platform-wide with the v1 sunset 2027-04-01; (b) keep `rda_` indefinitely | **(a)** |

## 11. Sources

Vendors and projects (checked 2026-10-02):

- GitHub self-hosted runners REST API (registration token, JIT config): https://docs.github.com/en/rest/actions/self-hosted-runners
- GitHub ephemeral runners: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/autoscaling-with-self-hosted-runners
- GitHub runner key generation (source): https://github.com/actions/runner/blob/main/src/Runner.Listener/Configuration/RSAFileKeyManager.cs
- GitHub Actions OIDC: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- Tailscale auth keys: https://tailscale.com/kb/1085/auth-keys ; key expiry: https://tailscale.com/kb/1028/key-expiry ; Tailnet Lock: https://tailscale.com/kb/1226/tailnet-lock ; workload identity federation: https://tailscale.com/docs/features/workload-identity-federation
- Teleport join methods: https://goteleport.com/docs/reference/deployment/join-methods/ ; bound keypair: https://goteleport.com/docs/reference/machine-workload-identity/bound-keypair/admin-guide/ ; tbot configuration: https://goteleport.com/docs/reference/machine-workload-identity/configuration/
- Kubernetes bootstrap tokens: https://kubernetes.io/docs/reference/access-authn-authz/bootstrap-tokens/ ; kubelet TLS bootstrapping: https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/ ; projected tokens: https://kubernetes.io/docs/concepts/storage/projected-volumes/ ; bound tokens: https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/ ; issuer discovery: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
- SPIRE server (attestors, TTLs): https://spiffe.io/docs/latest/deploying/spire_server/ ; concepts: https://spiffe.io/docs/latest/spire-about/spire-concepts/
- Vault AppRole: https://developer.hashicorp.com/vault/api-docs/auth/approle ; response wrapping: https://developer.hashicorp.com/vault/docs/concepts/response-wrapping ; Nomad workload identity: https://developer.hashicorp.com/nomad/docs/concepts/workload-identity
- Elastic Fleet enrollment tokens: https://www.elastic.co/guide/en/fleet/current/fleet-enrollment-tokens.html ; unenroll: https://www.elastic.co/guide/en/fleet/current/unenroll-elastic-agent.html
- CrowdStrike installer: https://developer.crowdstrike.com/falcon-sensor/scripts/powershell/install/
- Datadog Remote Configuration: https://docs.datadoghq.com/remote_configuration/ ; Uptane client: https://pkg.go.dev/github.com/DataDog/datadog-agent/pkg/config/remote/uptane
- Wiz sensor chart: https://github.com/wiz-sec/charts/blob/master/wiz-sensor/values.yaml
- Tenable linking key: https://docs.tenable.com/vulnerability-management/Content/Settings/Sensors/RegenerateLinkingKey.htm ; `nessuscli agent link`: https://docs.tenable.com/nessus/command-line-reference/Content/LocalAgentsCommands.htm
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
