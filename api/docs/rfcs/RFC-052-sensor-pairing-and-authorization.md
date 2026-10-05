# RFC-052: Sensor pairing and per-sensor authorization

| | |
|---|---|
| Status | Accepted (decisions SA-1..SA-6 and the secure defaults D-1..D-7, 2026-10-05); SP1 and SP2 in implementation |
| Scope | api, web, sdk-go (`pkg/sensorsig`, `pkg/sensorproto/pairing`, `pkg/sensorkit`, `pkg/httpsec`), sensor |
| Builds on | [RFC-032](RFC-032-sensor-enrollment-and-identity.md) (sensor-held Ed25519 key, RFC 9421 signatures, enrollment, `octs_`/`octe_`), [RFC-040](RFC-040-platform-sensor-mutual-distrust.md) (result binding, signed jobs, local ceiling), [RFC-023](RFC-023-scan-zones-and-scanners.md) (zones), [RFC-046](RFC-046-scans-redesign.md) and the stage catalog (tiers T0/T1/T2) |
| Architecture | [sensor-pairing.md](../architecture/sensor-pairing.md), [sensor-platform-trust.md](../architecture/sensor-platform-trust.md), [authorization-matrix.md](../architecture/authorization-matrix.md) |
| How-to | [pair-a-sensor.md](../how-to/pair-a-sensor.md) |

## 1. Summary

Two changes that make a sensor's identity and its privileges explicit.

**Pairing (SP1).** A new sensor needs only the platform URL (and, from the
install snippet, the fingerprint of the platform's certificate authority). It
creates its own Ed25519 key, asks the platform to pair, and prints a short
**pairing code** and a **fingerprint** (a short authentication string, SAS,
such as `821 · melon · basil · bagel`). An administrator enters the code in
**Sensors → Pair a sensor**, checks that the fingerprint on the screen is the
one on the sensor's console, sees the host facts and the address the request
came from, re-authenticates, and chooses the zone, role and **grant profile**.
Only then does the key become an identity in that organization. No secret is
ever typed, copied or pasted: the code and the fingerprint are useless to a
thief who does not hold the sensor's private key.

Every request of a paired sensor is signed with its key (RFC 9421 HTTP message
signatures, RFC 9530 `Content-Digest`); no bearer key exists for it.

**Grants (SP2).** Every sensor carries a **grant**: which zones, job types,
tools and capabilities, which tier (T0 passive, T1 active, T2 intrusive),
which targets, whether it may receive credentials, push results without a job,
or act on remote actions. The platform checks the grant on every poll, claim
and result, even for a job a person scheduled. New identities start at trust
level **New** (T0 only, no credentials, no push ingest) and stay there until an
administrator promotes them. Existing sensors get a **legacy-broad** grant that
keeps today's behaviour and is flagged in the console until someone narrows it.

```
 sensor host                       platform (unauthenticated, capped)          admin (console)
 ───────────                       ─────────────────────────────────           ───────────────
 key = Ed25519 (0600)
 POST /pairings  pub, H(nS), host ─▶ store (no tenant), code, nP, sig(P) ──┐
       ◀── pairing_id, code, P_pub, nP, sig, expiry                         │
 verify sig, pin                                                            │
 PUT /pairings/{id}/nonce  nS ─────▶ check H(nS); SAS = H(pub‖P‖nS‖nP)       │
 print  Code K7QM-4ZTD                                                       │
        Fingerprint 821 · melon · basil · bagel                             ▼
                                                     lookup code ◀── sensors:pair: shows SAS, host facts, IP
                                                     approve     ◀── sensors:approve + step-up +
                                                                     "fingerprint matches" + zone/role/profile
 GET /pairings/{id} (signed) ◀───── approved: sensor id, tenant, key id
 POST /pairings/{id}/complete (signed identity statement) ──▶ key active, audit, timeline, admins notified
 every later request: RFC 9421 signature, keyid = thumbprint
```

## 2. Decisions

Adopted per the owner's direction ("do the most secure, best option"):

| # | Decision |
|---|---|
| SA-1 | Interactive pairing with a short code and a SAS fingerprint compare is the default for manual installs; no secret is ever handled by a person. |
| SA-2 | Pairing, workload attestation (SP5) and the RFC-032 one-time token end in one state: a key-bound identity, authenticated per request by its key. |
| SA-3 | A per-sensor grant created from a profile, enforced server-side on every request. Effective permission = grant ∩ trust level ∩ the sensor's local ceiling ∩ the signed job. |
| SA-4 | Trust levels; new identities get no credentials, no push ingest and no T1/T2 work until promoted. Risk signals restrict automatically (SP3). |
| SA-5 | One identity = one tenant. Widening needs a stronger permission and is audited and notified; narrowing is instant. Time-boxed intrusive grants (SP4). |
| SA-6 | "Purge everything sensor X wrote since T" and kill switches are part of the design (SP3/SP4). |

Secure defaults (owner, 2026-10-05):

| # | Default |
|---|---|
| D-1 | **No automatic promotion.** A New sensor stays New until an administrator promotes it. A later tenant opt-in may auto-promote after N healthy hours for T0/T1 only; T2 and credentials always need an explicit administrator action. |
| D-2 | **Approval needs step-up re-authentication** (TOTP when the administrator has it, else the password, else a sign-in younger than 10 minutes for SSO-only accounts) and shows the fingerprint, host facts and source address. The approve button stays disabled until the administrator ticks "the fingerprint matches"; the API refuses an approval without `fingerprint_confirmed: true`. |
| D-3 | **Pairing codes**: 10-minute expiry, single use, 40 bits, per-address and global rate limits, a cap on open requests, uniform responses. |
| D-4 | **New organizations require key-bound identity**: no bearer (`octs_`) sensor key can be created in them. Existing organizations keep the option (migration sets it), existing bearer-key sensors keep working and are flagged "legacy key". |
| D-5 | **Profiles default to the narrowest**: no credentials, no push ingest, T2 off, remote actions only pause and drain. Widening needs `sensors:grant:widen`, is audited at high severity and notifies every administrator. Two-person approval of widening is SP4; the grant service has the hook (`WideningApprover`) and today approves with the single actor. |
| D-6 | **Everything is audited and on the sensor's timeline**: pairing requested/approved/denied/confirmed, re-pair, grant change (with a diff), trust change, credential refusal, out-of-grant claim refusal, key revocation. |
| D-7 | **Key at rest**: the private key is a 0600 file in a 0700 directory owned by the sensor's user. The sensor refuses to start when the permissions are looser (a preflight failure that names the fix). OS keystore / TPM storage is SP6. |

## 3. Current state (develop 1d4e6c3b9, sdk-go 2d7ab2a, sensor e40514d)

- RFC-032 Phases 1 and 2 (key-bound identity, enrollment tokens) are **not
  implemented**: no `sensor_keys`, no RFC 9421 verifier, no `octe_` route.
  Every sensor authenticates with a bearer key (`octs_`, legacy `rda_`) that an
  administrator created and pasted into an install command.
- Poll and claim are scoped by tenant, pin, zone, tool and capability, but the
  tool and capability gates trust what the sensor reports when the
  administrator set no limit; **claim by id does not check required
  capabilities** (`ClaimForSensor` has no capability predicate), so a sensor
  can claim a `validate:nuclei` command that poll would never have offered it.
- Results are bound to commands the sensor holds (`ingest.OpenCommand`);
  unsolicited reports are admitted by sensor role (collector, runner) and the
  tenant's result policy (`warn` / `quarantine`). There is no per-sensor
  switch.
- No platform-held credential is delivered to sensors, but `scanner_config` is
  forwarded verbatim and can carry a token a person typed (RFC-032 G7).
- Remote actions: `pause`, `rotate_key`, `cancel`, `send_manifest` are emitted;
  `drain` and `update` are reserved.
- Tenant users have no step-up primitive (the console has one for platform
  administrators).

## 4. Pairing protocol (SP1)

### 4.1 Endpoints

Sensor plane, unauthenticated by bearer key but every request **signed with
the key being paired** (§4.3). They live under `/api/v2/sensor/pairings` (the
sensor plane of RFC-041; the edge already routes `/api/v2/sensor/*` to the
API), outside the authenticated group:

| Method and path | Purpose |
|---|---|
| `POST /api/v2/sensor/pairings` | Start: public key, commitment to the sensor nonce, host facts, optional reverse-mode code, optional `sensor_id` (re-pair). Answers `201` with the pairing id, the user code (default mode), the platform key and nonce, the platform signature and the expiry. |
| `PUT /api/v2/sensor/pairings/{id}/nonce` | The sensor nonce; the platform checks it against the commitment and computes the SAS. |
| `GET /api/v2/sensor/pairings/{id}` | Poll: `pending`, `approved` (with the identity), `denied`, `expired`, `completed`. |
| `POST /api/v2/sensor/pairings/{id}/complete` | The sensor's signed statement accepting the identity; the key becomes active. |

User plane (tenant from the session, as every user route):

| Method and path | Permission | Purpose |
|---|---|---|
| `POST /api/v1/sensor-pairings/lookup` | `sensors:pair` | Find an open pairing by code: SAS, key fingerprint, host facts, source address, expiry. Uniform `404` for unknown, expired, used or foreign codes. |
| `POST /api/v1/sensor-pairings/expectations` | `sensors:pair` | Reverse mode ("expect a sensor"): returns a code for `openctemio-sensor pair <CODE>`. |
| `GET /api/v1/sensor-pairings/expectations/{id}` | `sensors:pair` | Poll an expectation: once the sensor connected, the SAS and host facts to compare. |
| `POST /api/v1/sensor-pairings/{id}/approve` | `sensors:approve` + step-up | Bind the key to a new sensor (or to the registration being re-paired) with the chosen name, type, zones, grant profile. Requires `fingerprint_confirmed: true`. |
| `POST /api/v1/sensor-pairings/{id}/reject` | `sensors:pair` | Refuse a pairing (audited). |
| `GET/PUT /api/v1/sensors/identity-policy` | read: `sensors:read`; write: `sensors:grant:narrow` to require key-bound identity, `sensors:grant:widen` to allow bearer keys again | D-4 switch. |

### 4.2 Exchange and the SAS

1. The sensor creates (or reuses, after a restart) its key `S` and a 32-byte
   nonce `nS`, and sends `S`, `C = SHA-256("openctem/sensor-pairing/commit/v1" ‖ 0 ‖ nS)`
   and its host facts.
2. The platform stores the request **without a tenant**, draws a 32-byte
   nonce `nP` and an 8-character code (Crockford base32, 40 bits; stored as a
   keyed HMAC, never in clear), and signs the transcript
   `"openctem/sensor-pairing/platform/v1" ‖ 0 ‖ id ‖ 0 ‖ S ‖ C ‖ P ‖ nP ‖ expiry`
   with the platform pairing key `P` (Ed25519, derived from the installation's
   encryption key with HKDF, info `openctem/sensor-pairing/platform-key/v1`).
3. The sensor verifies the signature (and `P` against a pinned fingerprint
   when the install snippet carries one), then reveals `nS`.
4. Both sides compute
   `d = SHA-256("openctem/sensor-pairing/sas/v1" ‖ 0 ‖ S ‖ P ‖ nS ‖ nP)`;
   the SAS is the number `(d[0]·256 + d[1]) mod 1000` (three digits) and the
   words `W[d[2]]`, `W[d[3]]`, `W[d[4]]` from a fixed list of 256 words
   (about 34 bits). The word list is part of the protocol; its SHA-256 is
   pinned in the test vectors.

**Why the commitment.** Without it, a man in the middle who sees `nS` could
try `nP` values offline until the SAS it shows the sensor equals the one the
platform shows the administrator (2^34 hashes: seconds). The sensor commits
to `nS` before it sees `nP`, and `nP` is fixed before `nS` is revealed, so an
attacker gets one guess (2^-34).

Test vectors (keys, nonces, commitment, SAS, platform signature, confirm
signature, code encoding and normalisation, and the RFC 9421 signature base
and header values) are one file, byte-identical in
`api/pkg/sensorproto/pairing/testdata/vectors.json` and
`sdk-go/pkg/sensorproto/pairing/testdata/vectors.json`; both test suites
check their implementation against it.

### 4.3 Request signatures (the RFC 9421 profile)

Shared by pairing and by every request of a key-bound sensor:

```
Content-Digest: sha-256=:<base64>:                        (when there is a body)
Signature-Input: sig1=("@method" "@path" "@query" "content-digest");created=…;expires=…;
                 nonce="…";keyid="<RFC 7638 thumbprint>";alg="ed25519";tag="openctem-sensor/v1"
Signature: sig1=:<base64 Ed25519 signature>:
```

- The verifier accepts exactly this shape (one signature, these components
  in this order, these parameters in this order, re-serialised and compared
  byte for byte) and refuses everything else.
- `expires − created ≤ 5 min`; clocks may differ by 2 minutes.
- The nonce is single-use per key within the window (Redis `SET NX`, a
  per-replica cache when Redis is unavailable).
- The body is checked against `Content-Digest` after the signature verifies
  (so an unauthenticated client cannot make the API buffer a body).
- `@authority` is not covered: gateways rewrite the host and the platform
  URL is configuration on both sides. `@path` is covered as dialed, so a
  gateway must not rewrite paths (the gateway smoke test checks it).
- A sensor with an active signing key has no bearer key; a bearer request for
  it can never match. A signed request for a key that is pending, revoked or
  whose sensor is revoked is refused with the same `401`.

### 4.4 Caps and uniform answers

| Limit | Value |
|---|---|
| Start requests per source address | 10 per hour (burst 3) |
| Start requests, whole platform | 600 per hour |
| Open (unclaimed) requests, whole platform | 1000; a start beyond it answers `503` with `Retry-After` |
| Reveal / poll / confirm per pairing | 1 per second (burst 5) |
| Lookups per administrator | 10 per minute; 20 failed lookups per hour lock lookups for that user for an hour |
| Expiry | 10 minutes from start; an approved pairing must be confirmed within 10 minutes of approval |
| Code | single use; a used, denied or expired code is never valid again |

Uniformity:

- A start with a reverse-mode code that is unknown, expired or used answers
  exactly like a valid one (`201`, same shape, no user code); the pairing then
  simply never gets approved and expires. The sensor's operator sees it wait;
  the administrator who created the expectation sees no sensor arrive.
- Lookup answers one `404 pairing_not_found` for unknown, expired, used,
  denied, already-claimed and other-tenant re-pair codes.
- Poll for an unknown pairing id, or with a key other than the pairing's,
  answers `404`.
- The pending request belongs to no tenant until an administrator claims it,
  so nothing about any organization can be learned through it.

### 4.5 Approval

`POST /api/v1/sensor-pairings/{id}/approve`:

```json
{
  "fingerprint_confirmed": true,
  "step_up": { "totp": "123456" },          // or { "password": "…" }
  "name": "dmz-scanner-01",
  "type": "worker",
  "zone_ids": ["…"],
  "grant_profile": "internal-network-scanner"
}
```

- `sensors:approve`; the pairing must be revealed (SAS known), open and not
  expired. The first claim wins (compare-and-set on the row).
- Step-up (D-2): the platform has TOTP for tenant users (RFC-024). An
  administrator with TOTP must give a current code; one without TOTP but with
  a password gives the password; an SSO-only account without TOTP must have
  signed in within the last 10 minutes. Failures count towards the account's
  lockout like a sign-in.
- In one transaction: create the sensor in the administrator's tenant (or
  load the registration being re-paired, which must be in the same tenant,
  else `404`), insert the key as `pending`, create the grant from the profile
  at trust level **New**, assign the zones (tenant-checked), mark the pairing
  `approved`.
- Audit `sensor.pairing_approved` (high), with the fingerprint, SAS, host
  facts, source address and the profile; timeline event; in-app notification
  to every administrator of the organization ("Sensor X was paired by Y from
  address Z; fingerprint F").

`complete` activates the key (`sensor.pairing_completed`). An approval not
confirmed within 10 minutes expires and its key is revoked.

### 4.6 Re-pair

A sensor that lost its key, or whose key is suspected stolen, starts a
pairing with `sensor_id`. Approval needs the same permission, step-up and
fingerprint check, plus the registration must be in the approver's tenant. On
approval every active key of that sensor is revoked (`revoked_reason =
repaired`), a bearer key on the row is cleared (the sensor becomes key-bound),
the trust level returns to New, and the history (keys, events, results) is
kept.

### 4.7 Sensor side

- `openctemio-sensor pair [CODE]` pairs and exits; without a code it prints
  the code and fingerprint for the administrator, with one it attaches to an
  expectation (reverse mode) and prints the fingerprint to compare in the
  console.
- The daemon pairs on first start when it has neither an identity nor a
  configured key, prints the same lines, waits for approval (a new request
  every 10 minutes) and then runs.
- `SENSOR_CA_FINGERPRINT` (from the install snippet) pins the platform's TLS
  chain to a certificate with that SHA-256 fingerprint; `SENSOR_PLATFORM_KEY`
  optionally pins the pairing key.
- Identity lives in `<state dir>/identity/`: `signing.key` (PKCS #8 PEM,
  0600) and `identity.json` (0600), directory 0700. Looser permissions, or
  another owner, stop the sensor with the exact `chmod`/`chown` to run.

## 5. Grants (SP2)

### 5.1 Model

One row per sensor in `sensor_grants` (composite foreign key on
`(tenant_id, sensor_id)`):

| Dimension | Column | Meaning (NULL = no limit from the grant) |
|---|---|---|
| Profile | `profile` | The profile it was created from (label only; the columns are the grant) |
| Trust | `trust_level` | `new` or `trusted` (SP3 adds `restricted`, `quarantined`) |
| Job types | `job_types` | `scan`, `collect`, `validate`, `connector_sync`, `connector_scan`, … |
| Zones | `zone_ids` | A zoned command must be in one of these zones |
| Tools | `tools` | The command's tool must be listed |
| Capabilities | `capabilities` | The command's required capabilities must be listed |
| Tier ceiling | `tier_ceiling` | `T0`, `T1` or `T2`; the command's tier (§5.3) must not exceed it |
| Target network | `target_network` | `any`, `public` (no private, loopback or internal-suffix targets) or `none` (no network targets: code and connector jobs only) |
| Target scope | `target_cidrs`, `target_domains` | Every target must lie in one CIDR or be one of the domains or below it |
| Credentials | `allow_credentials` | May receive jobs that carry credentials |
| Push ingest | `allow_push_ingest` | May send results without a job |
| Remote actions | `remote_actions` | Which gated actions the platform may send (`update`, `rotate_key`, `diagnostics`); `pause`, `resume`, `drain`, `cancel` and `send_manifest` only narrow and are always allowed |
| Version | `version` | Incremented on every change; the audit diff names old and new |

**Effective grant** = the row, then the trust level: `new` caps the tier at
T0 and turns credentials and push ingest off.

### 5.2 Profiles

| Profile | Job types | Tier | Targets | Credentials | Push ingest | Remote actions |
|---|---|---|---|---|---|---|
| `easm-external` | scan | T1 | public only | no | no | pause, drain |
| `internal-network-scanner` (default) | scan, validate | T1 | any, zones chosen at approval | no | no | pause, drain |
| `authenticated-scanner` | scan, validate | T1 | any, zones | yes (still off while New) | no | pause, drain |
| `collector:<integration>` | collect, connector_sync | T0 | none | no | yes (still off while New) | pause, drain |
| `ci-runner` | scan | T0 | none (code only) | no | yes (still off while New) | pause, drain |
| `endpoint-agent` | scan, collect | T0 | none | no | yes (still off while New) | pause, drain |
| `legacy-broad` | any | T2 | any | yes | yes | all |

`legacy-broad` exists only for sensors that existed before this RFC (the
migration gives it to all of them at trust level `trusted`, so nothing
changes for them). It cannot be chosen for a new sensor. The console flags it
("broad legacy grant: narrow it") on the list and the detail.

### 5.3 Enforcement

| Where | Check |
|---|---|
| Poll, claim-N, claim by id (v1 acknowledge, v2 claim) | The Go dispatch gate (`dispatchGate.refusal`, the one place poll, claim and acknowledge all pass) evaluates the effective grant against the command: job type, zone, tool, required capabilities, tier, target network, target scope, credentials. A refused command is not offered on poll and a claim by id fails `403 out-of-grant` (v1: `403 OUT_OF_GRANT`), audited (`sensor.claim_refused_grant`) with the dimension. The capability predicate is added to `ClaimForSensor` too (the gap in §3). |
| Command tier | The stage catalog's tier for the command's tool (lowest stage it implements); custom templates or out-of-band callbacks raise it to T2; an unknown tool is T2 (fail closed); `collect` and `connector_sync` are T0. |
| Credentials | A command whose `scanner_config`/`config` carries credential-looking values (the existing secret detector) needs `allow_credentials` and trust `trusted`; otherwise it is refused at claim (`sensor.credential_refused`, audited). Sealed credential delivery (RFC-032 Phase 3) will use the same gate. |
| Results with a job | Unchanged: bound to a command the sensor holds (`ingest.OpenCommand`), same tool. |
| Results without a job | A sensor whose effective grant has `allow_push_ingest = false` is refused (`403 push-ingest-not-granted`, v1 `403 PUSH_INGEST_NOT_GRANTED`) before the role and tenant policy are consulted; with it, today's path applies (role, tenant `warn`/`quarantine`, limited powers). |
| Remote actions | The heartbeat answer drops gated actions the grant does not list. |
| Grant changes | `sensors:grant:narrow` when every dimension is equal or narrower; `sensors:grant:widen` otherwise. A widening is audited at high severity and notifies every administrator; the SP4 hook asks a second approver. Narrowing takes effect on the next request. |
| Trust | Promote (`new` → `trusted`) needs `sensors:grant:widen`; demote needs `sensors:grant:narrow`. |

### 5.4 Permissions

| Permission | Owner | Admin | Member | Viewer | Admin-only (custom roles) |
|---|---|---|---|---|---|
| `sensors:pair` | ✓ | ✓ | | | ✓ |
| `sensors:approve` | ✓ | ✓ | | | ✓ |
| `sensors:grant:narrow` | ✓ | ✓ | | | ✓ |
| `sensors:grant:widen` | ✓ | ✓ | | | ✓ |
| `sensors:revoke` | ✓ | ✓ | | | ✓ |

`POST /api/v1/sensors/{id}/revoke` accepts `sensors:write` or
`sensors:revoke` (revoking only narrows). Business-unit scoped sensor
administration is SP4.

## 6. Threat model

Each line is a test in the implementation PRs.

| # | Threat | Control | Test |
|---|---|---|---|
| 1 | Install snippet leaks | It holds only the URL and fingerprints; a code is useless without the key | start without a key cannot approve/confirm |
| 2 | Attacker runs a sensor and talks an admin into approving it | Fingerprint + host facts + source address on the approval screen, `fingerprint_confirmed` required, step-up, trust New (T0, no credentials, no push), all admins notified | approve without the flag `400`; New sensor refused a T1 claim and a credential job |
| 3 | MITM or fake platform at first contact | CA pin from the snippet; the SAS covers both keys and nonces; commitment | vectors: changing any input changes the SAS; tampered platform signature refused by the SDK; pinned-CA mismatch refused |
| 4 | Code brute force, spam | 40-bit codes, 10 min, single use, per-address + global caps, open-request cap, per-admin lookup limit and lockout | rate-limit tests; used code `404` |
| 5 | Tenant enumeration | Pending requests have no tenant; uniform `201`/`404` | invalid reverse code gets the same shape; foreign re-pair `404` |
| 6 | Cloned key | Clone detection (RFC-032 E13) keeps working on instance ids; SP3 quarantines | existing tests |
| 7 | Stolen key | Revocation is read on every request; re-pair revokes | revoked key `401` |
| 8 | Replay | Nonce single use, 5-minute window, digest over the body | same nonce twice `401`; changed body `401` |
| 9 | Stolen code without the key | Poll and confirm need a signature by the pairing's key; the identity is bound to that key | poll with another key `404` |
| 10 | Admin who paired leaves | The sensor belongs to the organization; the audit keeps who did what | — |
| 11 | Compromised sensor claims other zones' or tools' jobs | Grant check on poll and every claim path; capability predicate on claim by id | out-of-grant claim `403` and audited, per dimension |
| 12 | Results for other jobs (BOLA) | `OpenCommand` (existing) | other sensor's command `command-not-found` |
| 13 | Push poisoning | Push ingest off unless granted and trusted | unsolicited report from a profile without push `403` |
| 14 | Credential exfiltration | Credential jobs only to trusted sensors with `allow_credentials` | credential job refused to New and to a grant without it |
| 15 | Scans outside scope | Target network and target scope in the grant, on top of the ownership gate and the local ceiling | private target refused to `easm-external`; target outside CIDRs refused |
| 16 | Insider widens a sensor | `sensors:grant:widen`, audit, notification, SP4 second approver | narrow-only actor refused a widening |
| 17 | Compromised platform orders an attack | RFC-040 separate signer and local ceiling (unchanged); the grant is defence in depth on the platform side | — |
| — | Cross-tenant access | Every query tenant-scoped; approval binds to the approver's tenant; grants and pairings of another tenant answer `404` | cross-tenant grant read/update `404`; re-pair of another tenant's sensor `404` |

## 7. Data and migrations

- `sensor_keys` (migration 001074): `(id, tenant_id, sensor_id, thumbprint UNIQUE, public_key, alg,
  status pending|active|revoked, created_at, activated_at, revoked_at,
  revoked_reason, last_used_at, last_used_ip)`, composite FK
  `(tenant_id, sensor_id)`.
- `sensor_pairings` (migration 001075): `(id, mode forward|reverse, tenant_id NULL until claimed,
  code_hash, public_key, thumbprint, commitment, sensor_nonce,
  platform_nonce, sas, host_facts, source_ip, sensor_id (re-pair target or
  created sensor), status, expires_at, approved_by, approved_at, …)`,
  indexed for the caps; rows older than 30 days are purged by the
  housekeeping job (audit keeps the record).
- `sensor_grants` (§5.1); the migration inserts a `legacy-broad`,
  `trusted` grant for every existing sensor in one statement.
- `tenants.sensor_bearer_keys_allowed boolean NOT NULL DEFAULT true`, then
  default changed to `false`: existing organizations keep bearer keys, new
  ones require key-bound identity (D-4).
- Permissions: the five new ids in `permissions`, granted to owner and admin,
  added to the admin-only list (Go, the custom-role trigger, web constants).

## 8. Plan

| Phase | Deliverable | Repos |
|---|---|---|
| SP1a | This RFC, architecture doc, matrix, how-to | api |
| SP1b | Key-bound identity: `sensor_keys`, the RFC 9421 verifier on v1 and v2, nonce store | api |
| SP1c | Pairing endpoints, SAS, approval with step-up, re-pair, permissions, identity policy (D-4), audit, notifications | api |
| SP1d | Signer, pairing client, identity store with permission checks, CA pin, auto-pair | sdk-go |
| SP1e | `openctemio-sensor pair`, auto-pair on first start, snippet variables | sensor |
| SP2a | Grants, profiles, trust New/Trusted, enforcement on poll/claim/results/credentials/remote actions, legacy-broad migration | api |
| SP1f/SP2b | Console: Pair a sensor (enter code / expect a sensor), fingerprint compare, step-up, grant view and narrow, legacy flags, identity policy | web |
| SP3 | Restricted / Quarantined, automatic signals, kill switches | api, sdk-go |
| SP4 | Two-person widening, time-boxed grants, BU-scoped sensor admin, purge-by-sensor, asset-group target scopes | api |
| SP5 | Workload attestation enrollment unified with CI trust rules; sensor pools | all |
| SP6 | Transport v3 certificates bound to the pairing key; keystore/TPM; key self-rotation | all |

## 9. Alternatives considered

| Alternative | Why not |
|---|---|
| Pairing that hands the sensor an `octs_` bearer key | A bearer secret would again exist on the wire and in logs (RFC-032 D3: no enrollment that issues bearer keys). |
| A code without a SAS | A phished approval of an attacker's sensor would be indistinguishable from the real one. |
| SAS without a commitment | Offline nonce grinding defeats a 34-bit SAS in seconds (§4.2). |
| A longer SAS (six words) | The commitment already limits an attacker to one guess; three words and three digits are what people actually compare. |
| Grants as JSON on the sensor row | Typed columns let the claim SQL and audits name the dimension and keep the diff exact. |
| Enforcing only in the sensor | The sensor is the party we must not trust; the platform enforces, the sensor's local ceiling adds the other half (RFC-040). |
