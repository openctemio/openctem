# RFC-040 — Mutual distrust between the platform and sensors

> Status: **Accepted** (2026-10-03; every recommendation in
> §9 approved). Proposed 2026-10-03 in #870. P0 implementation is split into the PR
> groups of §6.1: groups A, B and C merged; group D merged on the platform
> and in sdk-go/sensor `main`, not yet in a sensor release (§6.1).
> Amended 2026-10-08 (§11): review of every sensor → platform input, the
> outbound-only invariant, and decisions Q9–Q12 (Q3 revised for new installs).
> P1 signer (§5.6, Q11): the `openctem-signer` process (K1 key file, Unix
> socket, per-sensor `seq`, hash-chained signing log) and claim-time signed
> jobs on v2 and v3 are built, off by default (`SIGNER_SOCKET`):
> [architecture/job-signing.md](../architecture/job-signing.md). Sensor
> verification is in sdk-go (`pkg/jobsig`). P1.5 (K3, point 2): the offline
> root (`openctem-signer root keygen`), the root-signed, versioned key set
> that expires within 30 days (`openctem-signer keyset sign`,
> `SIGNER_KEYSET_FILE`, hello `signed_jobs.keyset`) and its ceremony are
> built; sensors pin the root (`SENSOR_JOB_SIGNING_ROOT` or at pairing).
> P2 scope ledger (§11.5, 2026-10-09): the signer keeps its own ledger of
> approved scope, fed by the scope service and checked at sign time
> (`enforce` for new installs, `audit` for upgraded ones until the
> bootstrap ceremony). Custom template versions are approved through the
> ledger and listed by digest in the signed job (§11.5).
> Scope: api (sensor gateway, signer, ingest pipeline, audit, detections) +
> web (output encoding) + sdk-go (job verification, local policy, credential
> providers, local audit) + sensor (`openctemio/sensor`) + helm-charts and
> install snippets (host hardening defaults).
> Gap analysis with code evidence:
> [architecture/sensor-platform-trust.md](../architecture/sensor-platform-trust.md).
> Consolidates, and does not repeat:
> [RFC-023](RFC-023-scan-zones-and-scanners.md) (D8 local allow-list, D9
> signed jobs, D11 no shell, D12 credential tiers, P5–P9),
> [RFC-031](RFC-031-managed-sensor-updates.md) (signed releases, content
> integrity), [RFC-032](RFC-032-sensor-enrollment-and-identity.md) (enrollment,
> Ed25519 identity, RFC 9421, HPKE-sealed credentials, the bearer-key
> sunset), [RFC-034](RFC-034-sensor-network-egress.md) (egress profiles and
> the in-sensor forwarder), [RFC-035](RFC-035-sensor-control-plane-under-load.md)
> (leases and fencing), [RFC-036](RFC-036-easm.md) (ownership gate, T0/T1/T2
> tiers) and [RFC-038](RFC-038-sensor-tool-settings.md) (signed tool
> settings).
>
> Requirement (2026-10-03): the sensor ↔ platform architecture must
> follow a **mutual-distrust** model. Compromising one side must not be
> enough to exploit the other: a compromised sensor must not be able to
> attack the platform, and a compromised platform (web, API or database) must
> not be able to weaponize sensors.

## 1. Answer in short

Today the trust is one-way and total in both directions:

- **Sensor → platform.** A sensor key is a bearer secret accepted by the same
  process, router, middleware chain and database pool that serve the admin
  API and the console. Authentication is solid (tenant from the key, per
  request, no cache), but most of what an authenticated sensor *writes* is
  not bound to work that was assigned to it.
- **Platform → sensor.** A sensor runs any well-formed command it receives
  over TLS. Nothing is signed; beyond a built-in deny list and an
  all-or-nothing private-range switch, nothing on the sensor host limits
  which networks it may scan; and platform-supplied templates run with the
  scanner's own signature check turned off. Whoever controls the API process, the `commands` table or
  the path controls every sensor of every tenant.

The design below makes each side **verify the other against something the
other cannot change**:

| Direction | The other side cannot change… | …so a compromise of it cannot… |
|---|---|---|
| Sensor → platform | the **sensor gateway**'s route table and database role, the lease that binds a result to a job, the size and schema limits, the output encoding in the console | reach admin routes or tables, write results for work it was not given, crash or poison the parser, run script in an analyst's browser |
| Platform → sensor | the **signing service**'s key and its scope ledger (widening needs two people), the **sensor-local policy file** written by the network owner, the host firewall, the vendor's release signature, the sensor-local vault, the owner's deploy window and kill switch | make a sensor scan outside the network owner's ranges, run anything but a typed scan, install unsigned code, read credentials, or erase the sensor's own record of what it was told |

The single most important property: **the network owner's local policy on
the sensor host is the last word.** A validly signed job that is out of that
policy is refused, logged locally and sent to the owner's SIEM. Signing
protects against path attackers and a compromised API or database; only
the local policy protects against an attacker who also holds the signing
key (RFC-023 §11 says the same).

## 2. Principles

| # | Principle |
|---|---|
| M1 | **Two boundaries, each enforced by the receiver.** The platform never trusts what a sensor sends; the sensor never trusts what the platform sends. Each side checks against its own state, not against claims in the message. |
| M2 | **Separate what is reachable from the network edge from what holds the crown jewels.** Sensor traffic terminates in a component that can do nothing else (the sensor gateway) and that never holds user sessions, tenant secrets or the job-signing key. |
| M3 | **Authorise every object, not only the caller.** A sensor may read and write only the commands it holds under a live lease, and results only for those commands (anti-BOLA). |
| M4 | **Results are hostile input** from the moment they arrive to the moment they are rendered: bounded, validated, parsed away from the request path, stored as text, encoded on output. |
| M5 | **Authority to act on a sensor is held outside the API.** Jobs, settings and key sets are signed by a separate signer whose key the API process cannot read; widening what may be scanned takes two people. |
| M6 | **The host owner has the last word.** A read-only local policy (ranges, ports, tools, tiers, credentials, hours, rate) and a host firewall are enforced on the sensor regardless of what is signed. |
| M7 | **Declarative jobs only.** No shell, no free-form arguments, no platform-chosen binaries, URLs or template sources; code comes only from releases signed by the vendor's build identity. |
| M8 | **Secrets by reference.** For authenticated scans the platform sends a reference; the sensor resolves it from a vault on its side. Sealed platform-held credentials (RFC-032 E10) stay an opt-in second tier. |
| M9 | **Independent records.** Each side keeps its own tamper-evident log and ships it to a place the other side cannot write: the platform's audit chain, and the sensor's local job log sent to the owner's SIEM. |
| M10 | **Compatible by default, stricter by switch.** Every control is additive; old sensors keep working until the tenant or the bearer-key sunset (§7) raises the floor. |

## 3. Current state, standards and incidents

### 3.1 Current state (summary)

Verified against `openctemio/openctem` `develop` b09dbf69, `openctemio/sensor`
`main` c97afb1 and `openctemio/sdk-go` `main` 411b664 on 2026-10-03. The
full table with file:line evidence and the attack each gap allows is in
[architecture/sensor-platform-trust.md](../architecture/sensor-platform-trust.md).

| Required control | Status | Gap rows |
|---|---|---|
| Separate sensor gateway | MISSING: same process, router, DB pool and role as the admin API | S1 |
| Per-sensor identity (proof of possession, enrollment token, short-lived, TPM, revocation) | per-sensor bearer key; revocation per request; the rest PLANNED in RFC-032 | S2a–S2e |
| Per-sensor object authorization | jobs: IMPLEMENTED; results: MISSING on v1, optional on v2; assets/findings not checked against the job | S3a–S3h |
| Results as hostile data | PARTIAL: size and (v2) schema limits; no field caps; parsing in-process; raw `href` from scanner data, permissive CSP | S4a–S4e |
| Broker / rendezvous | MISSING | S5 |
| Signed jobs, separate signer, nonce, two-person widening | MISSING (signing PLANNED in RFC-023 P5/P6); widening is one member action | P1a–P1d |
| Sensor-local read-only policy | PARTIAL: deny list and private on/off only; no CIDR, port or check-type allow-list | P2a, P2b |
| Declarative jobs, signed updates | no shell (IMPLEMENTED); platform-supplied custom templates run unsigned; images cosign-signed; content can be pinned older | P3a, P3b |
| Credentials by reference to a local vault | PARTIAL: none stored centrally by design; free-form config secrets travel in clear; no vault integration | P4 |
| Host firewall, no inbound, rate limit, kill switch | no inbound listener; no egress defaults; no local kill switch | P5a, P5b |
| Immutable OS + EDR, independent SIEM, audit, anomaly alerts | MISSING / PARTIAL: scope changes unaudited, unkeyed audit chain, no detections, stdout logs | B1–B4 |

The five highest risks (ranked in the architecture document §3):

1. **Unbound sensor writes.** Any sensor key writes assets and findings for
   any target of its tenant without a job, merges flags into existing
   assets, reopens human-resolved findings by fingerprint and attaches
   advisory evidence to any finding.
2. **No authority check between platform and sensor.** Commands are
   unsigned, the sensor has no local scope, and `POST /api/v1/commands`
   lets a tenant **member** send arbitrary scan targets to any sensor of the
   tenant with no scope, exclusion or zone check.
3. **Platform-supplied custom templates run unsigned**: nuclei's template
   signature enforcement is turned off for those runs, and the platform's
   template "signature" is an unverified HMAC keyed with
   `APP_ENCRYPTION_KEY`.
4. **One process and one database role** for sensor and admin traffic; the
   ingest worker is in-process and still processes reports from a sensor
   revoked after it queued them.
5. **Silent widening and rewritable history**: widening scope is one member
   action and is not audited, the audit chain is unkeyed, nothing alerts,
   and sensors log only to stdout.

### 3.2 Standards and incidents

Standards and public incidents reviewed for this design (2026-10-03), with
the surveys in RFC-023 §2 and RFC-032 §4.

| Source | What it shows | Taken here |
|---|---|---|
| **Uptane** two-repository model | An online **Director** issues per-device instructions on demand; a separately keyed **Image repository** (offline keys, run by people) publishes what is approved; under full verification the device acts only when both agree. A compromised Director can still choose among approved items or withhold work. | The API is the Director (which job, which sensor, when); the signer's ledger, approved by people and anchored in an offline or customer-held key, is the Image repository (§5.6 points 4–5); the sensor checks the job against **both** the signature and the signed scope document, then its own local policy (§5.7) |
| **TUF / Uptane roles and thresholds** | Roles can require several keys (a threshold); threshold 1 is allowed, so a quorum must be chosen, not assumed. Assume keys get compromised: minimal trust in online keys, expiry against freeze, monotonic versions against rollback, rotation and revocation through the root. | Offline root, expiring key set, `seq` + nonce + expiry per job (§5.6); the two-person rule is designed in deliberately (§5.6 point 5), and the root can be a 2-of-N threshold for installations that want it |
| **Vault Transit, AWS KMS** | Sign-as-a-service with non-exportable keys, Ed25519 included (`ECC_NIST_EDWARDS25519`; KMS raw messages ≤ 4096 bytes). Moving the key out of the API stops **theft**, not **misuse**: an API that can call "sign" gets anything signed. | K2 custody (§5.6 point 2); the signer applies its own ledger, rate and approval policy and is callable only by the core's identity |
| **Outbound-only scanner pairing** (common in scan engines) | Engines connect out to the console and poll; the console still decides what the engine does. | Outbound-only is today's model and stays; it shrinks network exposure but limits nothing a compromised console orders, which is why §5.6–§5.7 exist |
| **Shared linking keys** | One tenant-wide key entered on every scanner, with no signed tasks and no scanner-side scope. | Per-sensor enrollment and identity (RFC-032); signed tasks and a local scope protect sensors against a compromised console |
| **RMM supply-chain attack (2021)** | An authentication bypass on a remote-management server let attackers push a malicious "agent hot-fix" procedure to every managed endpoint, run from folders the product required anti-malware to exclude. | Agents must not run payloads just because the server sent them (§5.8: no exec, signed code only); never ask customers to exclude folders where pushed content is written and executed (§5.10: EDR exclusions narrow, no exclusion of the template or content directories) |
| **Remote-access console bypass, CVE-2024-1709 (2024)** | One flawed check in the management plane gave full admin; admin-level extension upload turned it into code execution. | Console-uploaded templates, scripts or tools must not reach sensors without a second signer and a sensor-side gate (§5.8; P0 local template gate) |
| **Trojanized signed updates (2020)** | Trojanized updates carried valid vendor signatures because the build itself was compromised: a signature proves origin, not safety. | Signature checks are necessary but not sufficient: the local allow-list and a second, separately held approval key are what limit a signed but hostile instruction (§5.6, §5.7); RFC-031 pins the release workflow identity and refuses downgrades |
| **Endpoint-sensor content update outage (July 2024)** | Validation only on the control side (a content validator with a logic bug) let malformed content crash about 8.5 million sensors; the fix added bounds and input-count checks **in the sensor**, canary testing, successive deployment rings with bake-in telemetry, rollback, and **customer control over when content deploys**. | Sensors re-validate everything pushed to them against their own schema (RFC-038 S7, §5.8) and a new item: **staged rollout rings, a customer-controlled deploy window and a local kill switch** for templates, settings and content (§5.12) |

## 4. Threat model

Assets: tenants' scan targets and network maps; scan credentials; the
integrity of findings, assets and auto-resolution; the console users'
sessions; the availability of the platform; the networks the sensors sit in
(a weaponized sensor is an attacker inside the customer's network); and the
records that prove what happened.

| # | Attacker position | Today | After this RFC (phase) | Residual |
|---|---|---|---|---|
| T1 | **Path attacker** trusted by the sensor (TLS-inspecting proxy, a CA added with `SENSOR_CA_CERT_FILE`, a rogue CA in the system store) | reads the bearer key and impersonates the sensor; injects or edits jobs (nothing is signed) | requests are RFC 9421-signed (no bearer secret, RFC-032 P1, a P0 dependency); jobs are DSSE-signed and verified against a pinned root (P1) | delay and drop |
| T2 | **Stolen sensor key**, used off-host | writes assets and findings for any target of the tenant, reopens resolved findings, reads unpinned jobs' targets, from any IP, for as long as the key lives | no bearer key after the sunset (RFC-032); clone and new-IP detection; writes only for commands it holds under a lease (P0/P1); unsolicited reports quarantined (P0) | a copied private key used while the original is offline looks legitimate until rotation (RFC-032 T2) |
| T3 | **Root on a sensor host** (compromised sensor) | all of T2, plus a direct line to the crown-jewel process's parsers and its DB role; can send pathological reports | talks to a gateway that serves only sensor routes with a narrow DB role (P1); parsing in a sandboxed worker (P2); results bound to its own jobs and targets (P0/P1); detections A1–A4 (P2) | can lie about results for the jobs it legitimately holds; can see those jobs' targets |
| T4 | **Approved third-party sensor** that turns malicious | same as T3 | same as T3; assurance level and push scopes limit what an unsolicited-push sensor may write (P1) | same as T3 |
| T5 | **Hostile scan target** (banners, titles, headers, hostnames, certificate fields) | rendered as React text (safe); markdown is never used for scanner findings; but scanner reference URLs become raw `href`, Jira receives raw wiki markup, CSP allows inline script | `safeHref` everywhere and a lint rule, CSP with nonces, ingest normaliser and field caps, escaping per ticketing format (P0/P2) | a convincing but honest-looking text in a finding |
| T6 | **Tenant member** account (phished, insider) | `POST /api/v1/commands` sends any target to any tenant sensor, bypassing scope exclusions and zones; deactivates or deletes exclusions alone; neither scope change is audited | raw scan commands go through the same target resolution as scans or are admin-only (P0); widening needs two other approvers (P2); every scope change audited and alerted (P0/P2); the signer and the local policy refuse targets outside the ledger and the owner's ranges (P1) | can request scans inside approved scope, as their role intends |
| T7 | **Tenant admin** account | everything in T6, plus custom nuclei templates that run unsigned and `allow_interactsh` | custom templates need a local opt-in on the sensor and a tenant template signature (P0/P3); widening still needs two other people (P2, WebAuthn-bound in P3); local policy caps tiers and ranges (P1) | two colluding admins can widen scope; the local policy still holds |
| T8 | **Database write** (SQL injection, stolen DB credentials, restored backup) | edits `commands` and sensors run them; rewrites the audit chain consistently (unkeyed hash) | unsigned or re-signed rows are refused by sensors that pinned a root (P1); the signer's ledger and sequence live outside the application DB (P1); audit checkpoints keyed outside the DB (P2) | can stop work or corrupt platform-side data; cannot direct sensors |
| T9 | **API process compromised** (RCE) | everything: every tenant's sensors, the encryption key, sessions, integrations | can ask the signer, which signs only targets inside the ledger, under rate and time-window ceilings (P1); widening requires WebAuthn assertions it cannot forge (P3); credentials are references (P2); the sensor's local policy is the last word (P1) | can run approved scans at the allowed rate (noise, not new reach); reads platform-side data |
| T10 | **Signer online key stolen** | n/a | key-set expiry ≤ 30 days and root-signed revocation (P1); KMS/HSM non-exportable keys (P3); local policy still applies | jobs inside the owner's local policy until the key set is revoked |
| T11 | **Platform operator insider** (SaaS) | same as T9 | same as T9; the offline root and the local policy belong to the customer, not to the operator | as T9 |
| T12 | **Release pipeline compromise** (sensor build) | images cosign-signed, but nothing on the sensor checks a release before running it (no self-update) | RFC-031 Part B: identity-pinned verification, no downgrade (P3) | an attacker with write access to the release workflow (RFC-031 §7) |

## 5. Design

Each item names the threat it stops, the design, migration and
compatibility, and its phase (§6). Items already designed elsewhere are
referenced, not repeated; this RFC only adds what is missing and fixes the
order.

### 5.1 Sensor gateway (sensor → platform)

**Threat.** A compromised sensor (or a stolen key) talks to a process that
also serves every admin and user route, holds the user-session secrets, the
tenant encryption key, the integration credentials and a database role that
can read and write every table. Any bug reachable from a sensor route (a
parser, a handler, a middleware) is a bug in the crown-jewel process. The
gateway in front (Caddy) forwards sensor and user paths to the same
upstream.

**Design.**

1. **Deployment mode first, separate binary later.** The API binary gains
   `SERVER_ROLE=sensor-gateway` (default `all`, today's behaviour; `api`
   serves everything except the sensor routes). In `sensor-gateway` mode
   `routes.Register` mounts **only** the sensor route table
   (`/api/v1/agent/*`, `/api/v1/agent/credentials/*`,
   `/api/v1/validation/evidence`, `/api/v2/sensor/*`, later
   `/api/v2/sensor/enroll`) plus `/health`; every other path is a 404 at the
   router, not a 401 from a middleware. The route table is one exported list
   shared by both modes and checked by the existing
   `route_authz_coverage_test` (a sensor route registered outside the list
   fails CI). A separate `cmd/sensor-gateway` with a reduced import graph
   (no user-auth, admin, integration or notification packages linked in) is
   Phase 3, once the mode has proven the split.
2. **Its own database role**, `openctem_sensor_gw`, created by a migration
   with explicit grants and nothing else: `SELECT` on the sensor, key, zone,
   suppression and command tables it reads; column-level `UPDATE` on the
   heartbeat, lease and command-state columns; `INSERT` on the ingest
   staging tables (`ingest_reports`, chunks, segments); `EXECUTE` on the
   audit-append function. **No** access to `users`, sessions, `credentials`,
   integrations, findings, assets or `audit_logs` directly. Writing findings
   and assets stays with the ingest workers in the core (§5.4), which run as
   the application role. A gateway compromise therefore yields: read of
   sensor rows and pending commands (already visible to sensors), and the
   ability to stage reports, which the core still validates. Row-level
   security on the gateway role (tenant from the authenticated sensor) is
   the natural first real user of the shadow-mode RLS policies, because the
   gateway's queries are few and all tenant-keyed.
3. **Its own Redis ACL user** limited to the rate-limit, nonce and doorbell
   key prefixes, and its own secrets: the gateway receives the sensor-key
   pepper and nothing else (no `APP_ENCRYPTION_KEY`, no JWT secret, no OIDC
   or SAML keys, no integration secrets). Because sealed credentials
   (RFC-032 E10) are sealed at claim time, the gateway needs the sealed
   blob, not the key that decrypted it: the sealing step moves to the core,
   which hands the gateway ciphertext only.
4. **Its own listener and hostname.** The built-in Caddy gateway routes
   sensor paths to the sensor-gateway upstream
   (`OPENCTEM_SENSOR_UPSTREAM`, default the API, so nothing changes until an
   operator sets it) and can serve them on a separate hostname or port
   (`OPENCTEM_SENSOR_HOSTNAME`) so that firewalls can expose only that name
   to sensor networks. Request-body ceilings at the edge match the API's
   route limits instead of a global 256 MB.
5. **DMZ deployment.** The gateway is stateless and can run in a DMZ with
   a database connection limited to its role. Where a DMZ may not open a
   database connection inward, Phase 4 adds the relay mode of §5.5: the
   gateway keeps a small local queue and the core connects **outward** to
   it.
6. **Mutual exclusion of credentials and routes**, already true in code and
   now tested on both processes: sensor keys are refused on every non-sensor
   route, user JWTs and `oct_` keys are refused on every sensor route
   (contract test per mode).

**Migration and compatibility.** No sensor-visible change: same paths, same
authentication. Single-container and all-in-one installs keep
`SERVER_ROLE=all`. The Helm chart gains an optional `sensorGateway`
Deployment (same image, different role and database secret); compose gains
a commented service. Operators move when they want the split.

### 5.2 Per-sensor identity

**Threat.** A bearer sensor key (`rda_`, and the interim `octs_`) copied off a host works from anywhere until
someone notices; nothing binds it to the host; admin-issued keys never
expire.

**Design.** RFC-032 as accepted (decisions D1–D5), unchanged:
enrollment tokens, sensor-generated Ed25519 keys, RFC 9421 signatures on
every v2 request, rotation, per-request revocation, clone detection,
assurance levels. Two decisions of 2026-10-03 amend RFC-032: the
interim bearer sensor key is `octs_` and the one-time enrollment token is
`octe_` (both base62 with a CRC32 checksum, replacing `rda_` for new keys
and `ocse_`), and **every bearer sensor key (`rda_` and `octs_`) is retired
90 days after RFC-032 P1–P2 (enrollment and key-bound identity) ship**,
instead of on 2027-04-01; existing sensors move from `rda_` to `octs_` on
auto-renew in the meantime. **RFC-032 P1–P2 is a P0 dependency of this
RFC**: a per-sensor key is what a signed job is addressed to (§5.6) and what
the object checks of §5.3 bind to. This RFC adds three points:

- **The gateway is the RFC 9421 verifier** (§5.1). With a dedicated sensor
  hostname, mTLS terminates at a component that is only for sensors, which
  removes one of the two deployment objections in RFC-032 §5.2 (the
  egress-inspection objection remains), so RFC-032 Phase 5 optional mTLS
  becomes cheaper: Caddy on the sensor hostname requires client
  certificates, the user hostname does not.
- **TPM- and keystore-held keys**: the RFC-032 `KeyStore` interface gets a
  PKCS#11 / TPM 2.0 implementation (Phase 5 there, unchanged), and the
  sensor's local policy can require it (`identity.require_hardware_key`).
- **Revocation reaches running work**: revoking or quarantining a sensor
  also re-queues its leased commands immediately (today a revoked sensor's
  work waits for lease expiry) and the gateway refuses its results.

**Migration.** As RFC-032 §7.

### 5.3 Object-level authorization for everything a sensor writes

**Threat.** Broken object-level authorization: an authenticated sensor
submits results, evidence or state changes for objects it was not given:
another sensor's command, a finding it never scanned, targets outside the
job, or another tool's findings to auto-resolve.

**Design.** One rule, enforced in the gateway handlers and again in the
core when a staged report is processed:

> A sensor write is accepted only if it names a command the authenticated
> sensor holds under a live lease (`commands.sensor_id = auth.sensor_id`,
> state `acknowledged` or `running`, `lease_epoch` current, or finished
> within the RFC-026 grace window), and its content stays inside that
> command: same tenant, same tool, targets within the command's targets
> (or discovered *from* them, see below), same kind of output.

- **Command transitions** (`acknowledge`, `start`, `complete`, `fail`,
  `release`): already bound to the holder and fenced by the guarded UPDATEs
  of RFC-035 D6 on v1 and v2; unchanged.
- **Results** (v1 ingest, v2 `PUT /results/{report_id}`): the report names
  its command (v2 already checks the holder when one is named,
  `commands/{command_id}/results/…`); the server checks the lease and stamps
  provenance from the command, never from the report. Reports **without** a command
  are accepted only from sensors whose role allows unsolicited pushes
  (`collector`, CI runner) and whose key scopes allow that data kind
  (RFC-014 Phase 4 scopes, finally enforced), into a quarantine state
  that never auto-resolves anything.
- **Discovered assets** outside the command's targets (subdomains, hosts on
  a scanned range) are stored as **candidates** in RFC-036's attribution
  model, never as confirmed assets, and never become scan targets without
  confirmation, so a sensor cannot plant targets.
- **Auto-resolve** happens only on commit of a command-bound report and only
  for the (tool, target) pairs that command covered (RFC-023 §10.8's
  "auto-resolve trusts the reported tool name" finding).
- **Validation evidence** is accepted only against a `validate` command
  assigned to the submitting sensor and still open (RFC-023 C-8).
- **Credential ingest** (`/agent/credentials/ingest`) follows the same rule
  as results.

**Migration.** The v2 SDK already sends command ids for scan results;
older sensors that do not are accepted for a compatibility window under a
tenant switch (`sensor_results_require_command`, default **off** until
P1 ships the SDK, **on** for new tenants, forced on at the
bearer-key sunset, §7).

> **As implemented (#889, migration `000317`).** The switch is the tenant
> result policy `mode`, `warn` or `quarantine`
> (`GET/PUT /api/v1/sensors/result-policy`), not a boolean
> `sensor_results_require_command`. Every tenant that existed at the
> migration got `warn` (unsolicited reports applied with the limits, audited
> and counted); a tenant with no policy row, so every new one, is
> `quarantine`. Advisory validation evidence is the policy's
> `allow_advisory_evidence` (default off). Review:
> `/api/v1/sensors/quarantined-results` (list, get, approve, reject). Details:
> [architecture/sensor-result-binding.md](../architecture/sensor-result-binding.md).

### 5.4 Hostile-results pipeline

**Threat.** Results are produced by scanners from attacker-controllable
input (banners, headers, page titles, TLS subject names, hostnames, CVE
descriptions on a target's own page). A compromised sensor can send
anything. The goals are: no denial of service of the platform, no parser
exploit in the crown-jewel process, no stored XSS or injection anywhere the
data is shown or exported.

**Design.**

1. **Bounded at the edge.** Per-request body limit at the gateway equal to
   the route's limit; decompression with a ratio and absolute cap
   (api#554 did this for chunks; extend to every compressed path); per
   sensor and per tenant quotas per hour (reports, items, bytes); JSON depth
   and item-count limits before allocation.
2. **Store first, parse later.** The gateway checks the envelope (media
   type, `Content-Digest`, size, command binding) and stores the bytes in
   staging. Parsing into domain objects happens in the asynchronous ingest
   workers (RFC-005), not in the request.
3. **Parse in a sandbox.** The ingest worker runs as its own process
   (`SERVER_ROLE=ingest-worker`) with: no listening socket, no outbound
   network except the database and Redis, a memory limit, a per-report CPU
   time budget, seccomp default profile, read-only root filesystem. A
   pathological report kills one worker, not the API.
4. **Normalise strings on the way in.** One sanitiser for every
   sensor-supplied string: valid UTF-8, no NUL, no C0/C1 controls except
   tab and newline, no bidi overrides (Trojan-Source), length caps per field
   (title, description, evidence, URL, hostname), URLs parsed and limited to
   the `http` and `https` schemes. Values are kept as
   text; nothing is ever stored as HTML.
5. **Encode on the way out**, audited once and then locked by lint:
   - web: no `dangerouslySetInnerHTML` (none today) outside one `SafeHtml`
     component that sanitises with DOMPurify; scanner text never rendered as
     markdown (true today: markdown only for human sources), and the
     markdown sanitiser refuses protocol-relative `//host` URLs; every `href`
     and `src` from data through the existing `sanitizeExternalUrl()`
     (http(s) only), enforced by a lint rule;
     CSV exports escape formula prefixes (`= + - @` and tab/CR; done, the
     server copy also learns to skip leading whitespace like the client);
     a Content-Security-Policy with script nonces instead of today's
     `'unsafe-inline'`, and `img-src` narrowed from `https:`;
   - api: HTML (reports, e-mail) only through `html/template`; ticketing
     (Jira wiki markup, Markdown in GitHub issues) and chat (Slack mrkdwn)
     escape their own markup characters; log lines strip `\r\n` (the
     CodeQL-recognised barrier).
   The current results of that audit are in the architecture document; this
   RFC's P0 fixes what it found.

**Migration.** Internal only. The worker split is a deployment option like
the gateway (default: in-process, as today).

### 5.5 Broker / rendezvous (optional)

**Threat.** Some networks allow neither inbound connections to the platform
from sensor zones nor inbound connections to the sensor; and some operators
do not want any inbound port on the core.

**Design.** Two shapes, both optional, Phase 4:

- **Relay mode of the gateway**: the gateway runs in the DMZ with a small
  durable queue (jobs out, results in). Sensors connect outbound to it as
  today; the **core connects outbound** to the gateway to fetch staged
  results and push signed jobs. The core then needs no inbound port at all.
- **External broker** (NATS JetStream or an HTTPS mailbox) with per-sensor
  subjects and per-tenant accounts, for operators who already run one.

Because jobs are signed end to end (§5.6) and results are RFC 9421-signed
by the sensor and bound to commands (§5.3), the broker is **untrusted for
integrity**: it can delay or drop, not forge. Credentials stay sealed or by
reference. That is the property that makes a rendezvous point acceptable in
a DMZ.

### 5.6 Signed jobs from a separate signing service (platform → sensor)

**Threat.** Anyone who can write the `commands` table (SQL injection, a
stolen database credential, a restored backup), run code in the API
process, or sit on the path decides what every sensor scans, with which
tool, settings and credentials.

**Design.** RFC-023 D9/P5/P6 decided *that* jobs are signed. This RFC
decides *who* signs, *what* exactly, and *what the signer refuses*.

1. **The signer is a separate service**, `openctem-signer`: its own
   container, its own key, no access to application tables, reachable only
   from the core over a Unix socket or mTLS on an internal network. The
   API (or the dispatcher) sends it a **job statement**; the signer
   validates it against its own state and returns a signed envelope, or
   refuses with a reason that is audited on both sides.
2. **Key custody options** (installation choice):

   | Option | Where the online key lives | Protects against | Fits |
   |---|---|---|---|
   | K1 (default) | file in the signer container (0400, its own volume/Secret, not mounted into the API) | API RCE, SQL injection, DB theft, backup restore, path attacker | single-node and compose installs |
   | K2 | cloud KMS (AWS KMS `ECC_NIST_EDWARDS25519`), Vault Transit, or an HSM via PKCS#11: non-exportable key; ECDSA P-256 where Ed25519 is not offered (every envelope carries its algorithm, RFC-023 P11). KMS raw signing is limited to 4096 bytes, so with K2 the DSSE payload is a compact **job statement** carrying the SHA-256 of the full job document, which travels beside it and is checked by the sensor | additionally: theft of the signer's disk. Not misuse: the signer's own policy (point 4) is what stops an API that can call it | enterprise, regulated |
   | K3 (always, on top of K1/K2) | **offline root** key held by the installation owner signs a **key set** (`signers.json`: online key ids, algorithms, `not_after`, monotonic `version`, expiry ≤ 30 days) | rotating or revoking an online key without re-enrolling the fleet; limits a stolen online key to its expiry | every installation; research 03 findings 1–3 |

   The sensor pins the **root** fingerprint: from its local policy file
   (§5.7) when the network owner writes it (strongest), otherwise at
   enrollment (RFC-032 T7, trust on first use). Key sets reach the sensor
   through the doorbell (`config_version`) and are verified against the
   root, version-monotonic and expiring, as TUF prescribes. go-tuf v2 is
   the reference verifier; a hand-written verifier
   must pass its test vectors.
3. **What is signed: the full declarative job, as the exact bytes the
   sensor will execute.** A DSSE envelope (payload type
   `application/vnd.openctem.job.v1+json`, Ed25519 over the PAE of the
   payload bytes; **no canonical-JSON re-serialisation**, the nuclei
   CVE-2024-43405 lesson):

   ```json
   {
     "kind": "openctem.job/v1",
     "tenant_id": "…", "sensor_id": "…", "command_id": "…",
     "run_id": "…", "chunk": {"index": 3, "of": 12},
     "lease_epoch": 2,
     "tool": "nuclei", "tool_version_min": "3.4.0",
     "tier": "T1",
     "profile": {"id": "…", "digest": "sha256:…"},
     "settings": {"version": 42, "digest": "sha256:…"},
     "targets": ["203.0.113.10", "app.example.com"],
     "ports": "80,443,8443",
     "zone": {"id": "…", "ranges": ["203.0.113.0/24"]},
     "exclusions": ["203.0.113.66/32"],
     "limits": {"rps": 50, "max_runtime_s": 3600},
     "egress": {"profile_id": "…", "revision": 7},
     "credential_refs": [{"provider": "vault", "ref": "kv/scan/web-basic"}],
     "issued_at": "2026-10-03T10:00:00Z",
     "expires_at": "2026-10-03T11:00:00Z",
     "nonce": "…", "seq": 18234,
     "signer": {"keyid": "…", "keyset_version": 5}
   }
   ```

   The envelope is produced **at claim time**, because only then are the
   sensor, the chunk (RFC-030 cuts chunks at claim) and the lease epoch
   known; RFC-032 seals credentials at the same moment. The claim reaches
   the core's dispatcher, which asks the signer and returns the envelope in
   the claim response; with the gateway split (§5.1) the gateway forwards
   the claim to the core over the internal link and **never talks to the
   signer itself**. A signer that is down means claims wait, not unsigned
   jobs.

   The sensor executes **only** the verified payload: the unsigned command
   fields (if any) are ignored, never merged. Tool settings stay a separate
   RFC-038 document, bound here by `settings.version` and `digest`, so a
   job cannot run with settings the signer did not see. RFC-038's settings
   documents and RFC-034's egress policy echo are signed by the same signer
   with the same envelope; RFC-038 S6 is amended to DSSE over exact bytes
   instead of canonical JSON.
4. **What the signer checks before signing** (its own state, not the
   API's): the tenant and sensor exist in its **ledger** (a small store
   only the signer writes: tenant scope roots, zone ranges, sensor ids and
   their zones, per-sensor `seq`); targets ⊆ the tenant's approved scope ∩
   the zone's ranges, minus exclusions; `tier` ≤ the scope's approved tier
   (RFC-036 T0/T1/T2); expiry ≤ 24 h; rate ceilings per tenant (jobs and
   distinct targets per hour) and a **time window** if the tenant set one;
   credential references only for ranges the ledger allows them on. It then
   assigns `seq` (monotonic per sensor) and `nonce`, signs, and appends to
   its own hash-chained signing log (exported to the SIEM, §5.11).

   **Two repositories, as in Uptane.** The approved part of the ledger
   (scope roots, zone ranges, tiers, credential-reference ranges, allowed
   tools and template digests) is published to sensors as a **scope
   document** per tenant and zone, signed by the approval authority (the
   offline root's delegated `scope` role; from Phase 3 the approvers'
   WebAuthn assertions are attached), versioned and expiring like the key
   set. The sensor runs a job only if the signer's job envelope **and** the
   current scope document agree (targets, tool, tier and credential
   references inside the scope document), and then only if its local
   policy agrees too. A signer whose online key is stolen can therefore
   sign jobs, but only inside the last scope that people approved.
5. **Two-person rule for widening.** The ledger changes only through
   change requests. **Narrowing** (removing ranges, lowering a tier,
   revoking a credential reference, removing a sensor) needs one approver.
   **Widening** (adding a range or domain root to scope or a zone, raising a
   tier, enabling a credential reference for a range, adding a sensor to a
   zone, removing an exclusion) needs **two distinct people**, neither of
   them the requester, both with `scope:approve`. Phase 2 records the
   approvals through the API (stops a single malicious or phished admin).
   Phase 3 makes each approval a **WebAuthn assertion over the change
   digest**, verified by the signer against approver credentials enrolled
   through the signer's own CLI at installation, so that even a fully
   compromised API cannot forge an approval. EASM confirmations
   (RFC-036) that add assets outside an approved root are widening.
6. **What the sensor checks** (SDK, before parsing anything else): envelope
   signature against a current key set signed by the pinned root; payload
   type; `sensor_id` and `tenant_id` are its own; `issued_at` within clock
   skew, `expires_at` in the future; `nonce` unseen (kept until expiry);
   `seq` greater than the last accepted (persisted, gaps allowed, so replays
   and rollbacks fail); `lease_epoch` matches the claim; settings digest is
   the applied document's; the job lies inside the current signed scope
   document; then the local policy (§5.7). Any failure:
   refuse, report `job-refused` with the reason, write the local job log.

**Migration and compatibility.** The envelope is additive on v2 commands
(RFC-023 C7). A sensor with `signed_jobs` in its features and a pinned root
**requires** signatures once the platform advertises the signer in `hello`;
new enrollments get `require_signed_jobs: true` by default; older sensors
keep receiving unsigned commands until the tenant raises the minimum or the
bearer-key sunset (§7). Unsigned commands are never sent to a sensor that has
pinned a root. Installations without a signer keep today's behaviour and
see a warning on the Sensors page.

### 5.7 The sensor-local policy file

**Threat.** A compromised platform **with** the signing key (or a signer
compromise, or a mistaken widening approved by two people) sends validly
signed jobs to scan a network the sensor's owner never agreed to, or to use
a tool, tier, port range or credential the owner forbids.

**Design.** RFC-023 D8 decided an operator-set allow-list intersected with
the job; RFC-034 §6.4 added the host's egress veto. This RFC makes them one
file.

> **Version requirement.** The P0 subset is enforced by sdk-go#140 and
> sensor#119, merged after sensor **v0.8.0**. Sensor v0.8.0 and older ignore
> `SENSOR_LOCAL_POLICY`, the policy file and the kill-switch file: the
> install snippets that mount the file need a sensor release later than
> v0.8.0 to have any effect.

```yaml
# /etc/openctem/sensor-policy.yaml  (root:root 0644, mounted read-only)
apiVersion: openctem.io/sensor-policy/v1
signer_root: "SHA256:3f1c…"        # pin; overrides trust on first use
require_signed_jobs: true
targets:
  allow: ["10.20.0.0/16", "203.0.113.0/24", "*.corp.example.com"]
  deny:  ["10.20.5.0/24"]          # built-in deny (loopback, link-local/IMDS,
                                   # ::/128, multicast, the platform) always applies
ports:   { allow: "1-1024,3389,5432,8000-8999" }
tools:   { allow: [nuclei, httpx, naabu, dnsx, subfinder, trivy] }
tiers:   { max: T1 }               # RFC-036: T2 (default logins, fuzzing) needs local opt-in
templates: { custom: deny }        # platform-supplied custom templates (local gate)
credentials:
  allow_refs: true
  providers:
    vault: { address: "https://vault.corp:8200", auth: approle, role_id_file: "/etc/openctem/vault-role" }
  ranges: ["10.20.0.0/16"]         # credentials only for these targets
schedule: { allow: "Mon-Fri 08:00-20:00", tz: "Europe/Paris" }   # optional
rate:   { max_pps: 2000, max_concurrent_jobs: 4 }
kill_switch_file: /etc/openctem/STOP   # present = refuse all jobs, finish none
identity: { require_hardware_key: false }
logging:
  job_log: /var/log/openctem/jobs.log   # local, hash-chained
  siem: { syslog: "tls://siem.corp:6514" }
```

- **Who writes it:** the network owner at install time (Helm value rendered
  into a ConfigMap mounted `readOnly`, compose bind mount `:ro`, a package
  file owned by root). The sensor process runs as a non-root user and
  cannot change it; the platform has no route to change it. A changed file
  takes effect on restart (or SIGHUP) and is logged locally.
- **Visibility:** the sensor reports the policy **digest and a summary**
  (ranges, tools, tiers, credentials yes/no) in its RFC-033 manifest, so
  the platform routes only jobs the sensor will accept and the UI shows
  "locked by the sensor owner". The report is informational; enforcement is
  local.
- **Enforcement points**, all in the SDK so third-party sensors inherit them
  (RFC-023 D19):
  1. **Job admission**, after the signature check and before any tool
     starts: every target, port, tool, tier, credential reference and the
     time window against the policy; a single violation refuses the whole
     job (`out-of-local-policy`, with the offending item), never a silent
     partial run.
  2. **Guarded resolver and dialer** for in-process scanners: resolved
     addresses checked against `targets` and the built-in deny list, then
     pinned (no DNS rebinding).
  3. **The egress forwarder** (RFC-034 §6.5), extended from proxied jobs to
     **every job of a proxy-aware tool**: tools reach the network only
     through the loopback forwarder, which applies job targets ∩ zone ∩
     local policy to each connection, including redirects and crawls.
  4. **The host firewall** (§5.10) rendered from the same file
     (`openctem-sensor policy render nftables|iptables|networkpolicy`),
     because raw-socket tools (SYN scans, ICMP, UDP) cannot be forced
     through a userland forwarder; it is the only control independent of
     the sensor process itself.
- **Missing file:** today's behaviour (no local limits), with a startup
  warning and a fleet-health flag `no_local_policy`. A tenant can require a
  policy before private targets are dispatched (RFC-023 R3).

**Migration.** `--allowed-ranges` / `SENSOR_ALLOWED_RANGES` (RFC-023 D8)
becomes a shorthand that writes `targets.allow` in memory. Old SDKs ignore
the file; the manifest of a sensor without a policy says so.

### 5.8 Declarative jobs and signed code

**Threat.** The platform turns a sensor into a remote-execution agent:
free-form tool arguments, platform-supplied templates that execute code
(nuclei `code`, `headless`, `file` protocols), platform-chosen download
URLs, or a pushed binary.

**Design** (RFC-023 D11 and RFC-031 D2/D11/D12 made explicit, and closed):

- **No shell, no exec**: the job has no field that names a binary, a path,
  an environment variable or a shell string. Tools are a closed set compiled
  into the sensor build.
- **No free-form arguments**: options are RFC-038 typed settings mapped to
  fixed flags by each adapter. The legacy free-form `scanner_config` /
  profile `options` map is frozen (no new keys honoured), then removed at
  the bearer-key sunset. Until then the sensor's denylist of dangerous flags stays,
  and the policy file can set `extra_args: deny`.
- **Templates**: platform-supplied custom templates are off unless the
  local policy allows them; when allowed, they must be signed by the
  tenant's template-signing key (held by the signer, approved like a scope
  widening), and template protocols that execute code or read local files
  are refused regardless.
- **Code updates**: only RFC-031 Part B (cosign keyless identity of the
  sensor release workflow, no downgrade, self-test, rollback); content only
  from sensor-local sources with publisher signatures (RFC-031 Part A). The
  platform can choose **which signed release and when**, never **what**.

### 5.9 Credentials by reference

**Threat.** Scan credentials stored on the platform are exposed by a
platform compromise; sent in jobs they are exposed to every component that
handles the job.

**Design.** RFC-023 D12 defined tiers; this RFC makes **T1 (reference)
the recommended default for authenticated scans** and specifies it:

- The platform stores a **credential reference**:
  `{provider, ref, scope_ranges, label}`, never a value. Providers resolved
  **on the sensor**: HashiCorp Vault (KV v2, dynamic SSH/DB secrets;
  AppRole or Kubernetes auth), CyberArk (Central Credential Provider or
  Conjur), a local file, or the OS keyring. Provider endpoints and
  authentication live in the sensor-local policy (§5.7), not on the
  platform.
- The job carries `credential_refs`; the signer allows a reference only for
  ranges the ledger approved; the sensor allows it only for ranges its
  policy lists, resolves it at job start, holds it in memory for that job,
  and never writes it to the outbox, logs or results. Leasing secrets
  (Vault dynamic credentials) are revoked at job end.
- **T2** (platform-held, HPKE-sealed to a key-bound sensor at claim time,
  RFC-032 E10) remains for tenants without a vault, and is refused by a
  sensor whose policy says `credentials.platform_held: deny`.

**Migration.** New tables for references; the existing secret-looking
`scanner_config` warning (RFC-032 G7) points to references once they ship.

### 5.10 Sensor host hardening (guidance and defaults)

**Threat.** A compromised sensor host is the attacker's foothold in the
customer's network; a compromised platform tries to use the sensor host as
one.

**Design.** A hardening guide in the sensor documentation, and the defaults
in the chart and snippets:

| Control | Default / guidance |
|---|---|
| Egress | allow only the sensor gateway on 443 and the policy's target ranges; DNS only to the configured resolvers; rendered from the policy file (§5.7 point 4); Kubernetes `NetworkPolicy` egress in the chart |
| Inbound | none. Health and metrics on loopback or a Unix socket; Kubernetes probes use `exec`. No pprof in release builds |
| Process | non-root user, read-only root filesystem, `cap_drop: [ALL]` plus `NET_RAW` only when a SYN-scan tool is enabled, `no-new-privileges`, seccomp `RuntimeDefault` |
| OS | immutable, minimal: Flatcar, Bottlerocket, Talos or Fedora CoreOS for dedicated hosts; distroless/Wolfi images; automatic security updates |
| EDR | supported and recommended on sensor hosts; the docs list the scanner processes and their expected network behaviour so EDR exclusions are narrow, and **never exclude the template, content or work directories** where pushed content is written and run (the 2021 RMM supply-chain lesson, §3.2) |
| Rate and kill switch | `rate.max_pps` and `max_concurrent_jobs` in the policy; `kill_switch_file` (or `openctem-sensor stop-all`) refuses new jobs and stops running ones, locally, without the platform |
| Time | NTP required (signatures and expiry, RFC-032 T12) |
| Logs | stdout plus an **independent SIEM sink** (syslog RFC 5424 over TLS, or OTLP) configured locally; the platform cannot turn it off |

### 5.11 Audit and anomaly detection (both directions)

**Threat.** A slow or partial compromise on either side goes unnoticed.

**Design.**

- **Platform audit** (hash-chained, already used for sensors): every scope,
  zone, exclusion, tier, credential-reference, egress-profile, tool-setting
  and job-template change with a diff; every change request and approval;
  every signer refusal; every command created (who or which schedule, the
  target count, the tool) at `info`, summarised per run.
- **Signer log**: every signature and refusal, hash-chained, exported to
  the SIEM by the signer itself (not through the API).
- **Sensor job log**: every job received, accepted or refused (statement
  digest, reason), hash-chained on the host and shipped to the owner's SIEM.
  This is the record a compromised platform cannot rewrite.
- **Detections** (platform side, raised as alerts and sensor health flags):

  | # | Signal | Why |
  |---|---|---|
  | A1 | A sensor credential used on a non-sensor route (404/401 counted per sensor at the gateway) | probing beyond its role |
  | A2 | Signature or replay failures above a small rate; clock skew jumps | stolen key, MITM, replay |
  | A3 | Results for commands the sensor does not hold; reports without a command from a scanner-role sensor | BOLA attempts |
  | A4 | Assets or findings outside the job's targets above a ratio; result volume or size far above the sensor's baseline | poisoning, DoS |
  | A5 | Key used from a new IP/ASN; two instances (clone, RFC-032 E13) | credential theft |
  | A6 | Sensor version, build digest or tool list regresses or changes without a release | tampering |
  | A7 | Scope widened, or a new range targeted for the first time | weaponisation |
  | A8 | Jobs created outside the tenant's working hours or outside a schedule | an attacker using a stolen session |
  | A9 | A burst in distinct targets, ports or tier T2 jobs per tenant | mass scanning |
  | A10 | Signer refusals (out of ledger, over rate) | the API asking for something it should not |
  | A11 | A sensor reports `out-of-local-policy` refusals | the platform asked for something the owner forbids |
  | A12 | Many enrollment failures from one address (RFC-032 T9) | enrollment abuse |

- **Detections** on the sensor (to the SIEM): unsigned, expired, replayed or
  out-of-policy jobs; a key set or root change; the policy file changed;
  the kill switch used.

### 5.12 Staged rollout, deploy window and kill switch for pushed content

**Threat.** Content pushed from the platform (custom templates, RFC-038
tool settings, RFC-031 content pins and refreshes, signer key sets and
scope documents) is malformed or malicious and reaches every sensor at once:
the July 2024 sensor-content failure mode (validated only on the control side,
deployed to everyone at the same time) and the 2021/2024 compromised-console
mode (pushed by a compromised console).

**Design.**

- **Re-validate on the sensor** before activation, against the sensor's own
  schema and limits (RFC-038 S7; template parser and protocol allow-list,
  §5.8; size and count caps), never relying on the platform's validator.
  Activation is all-or-nothing per document, and the last good version is
  kept for rollback.
- **Rings.** Every pushed document carries a `rollout` block: ring (canary →
  early → broad), the earliest activation time per ring, and the bake-in
  period. The platform promotes a version to the next ring only after the
  previous ring reports `applied` with no error and no health regression
  for the bake-in period; a failure halts promotion and offers rollback (a
  new version that restores the previous content, version numbers still
  only go up). Sensors are assigned to rings by the tenant (default: one
  canary sensor per zone, then everyone).
- **Customer-controlled deploy window** in the sensor-local policy:
  `content: { deploy_window: "Sat 02:00-06:00", auto_apply: [settings],
  hold: [templates] }`. A sensor does not activate held kinds outside its
  window; the platform shows "waiting for the owner's window" instead of
  forcing it. Security-critical narrowing (a key-set revocation, a scope
  narrowing) is exempt: it always applies at once.
- **Local kill switch** (§5.7 `kill_switch_file`, plus
  `content_freeze_file`): the host owner can stop all jobs, or freeze
  content at the current version, without the platform.

**Migration.** Old sensors ignore the `rollout` block and apply as today;
rings then only order the platform's pushes. Phase 2 (rings and window),
the kill switch is P0.

## 6. Phases

Ranked by risk reduced per unit of work. Each phase is a set of PRs, CI
green and verified end to end against a real sensor, as in RFC-032 §8.

| Phase | Item | Repos | Effort | Risk reduced |
|---|---|---|---|---|
| **P0 — close what is exploitable now (no new protocol)** | **Dependency: RFC-032 P1–P2** (key-bound identity + enrollment, `octs_` / `octe_`), already accepted and in progress; the bearer-key sunset follows 90 days after it ships | api, sdk-go, sensor, web, helm | L (tracked in RFC-032) | T1, T2; the identity every later check binds to |
| | `POST /api/v1/commands`: `scan` commands go through scan target resolution (exclusions, zone routing, private-address check) or are restricted to owners/admins; `UpdateScan` runs the config validator | api | S | T6 (member bypass) |
| | Result binding, cheap part: unsolicited v2 results only from `collector`/CI roles; tenant switch `sensor_results_require_command` (on for new tenants); advisory evidence off by default; scan sessions and ingest-job status scoped to the sensor; sensor reports never change compliance, classification, PII/PHI or exposure flags of an existing asset and do not reactivate archived assets; auto-reopen and auto-resolve only from command-bound reports of the same tool; legacy "no tools declared" auto-resolve off | api | M | T2, T3, T4 |
| | The ingest worker re-reads the sensor's status before processing a queued report; revoking a sensor re-queues its leased commands | api | S | T2, T3 |
| | Sensor-side local gates, default **off for new installs**: `SENSOR_ALLOW_CUSTOM_TEMPLATES`, `SENSOR_ALLOW_INTERACTSH`; `SENSOR_ALLOWED_RANGES` and `SENSOR_ALLOWED_PORTS` intersected in `ScanTargetPolicy` (RFC-023 D8 layer 3); a local kill-switch file; a cap on `timeout_seconds` | sdk-go, sensor | M | T6–T9 |
| | Audit scope targets, exclusions, tools and scanner templates; alert on scope widening (A7) | api | S | T6, T7 |
| | Output encoding: `safeHref` on every data-driven `href`/`src` plus an ESLint rule; CSP `img-src` narrowed; markdown URL check refuses `//host`; Jira text escaped; server CSV skips leading whitespace like the client | web, api | S | T5 |
| | Hardening defaults: snippets and chart set `runAsNonRoot`, `readOnlyRootFilesystem`, `cap_drop: [ALL]` (+`NET_RAW` only for SYN scanning), `no-new-privileges`, seccomp `RuntimeDefault`; an optional sensor egress `NetworkPolicy`; the hardening guide (§5.10) | api snippets, helm-charts, docs | S | T3, posture |
| **P1 — authority outside the API** | `openctem-signer` with K1 custody and the offline root key set; DSSE job envelopes; sensor verification (sig, key set, ids, expiry, nonce, `seq`, lease epoch); `require_signed_jobs` for sensors with a pinned root; RFC-038 settings and RFC-034 egress policy signed by the same signer | api (new cmd), sdk-go, sensor | L | T1, T8, T9 |
| | Sensor-local policy file v1 (§5.7) with manifest echo, the job log and the SIEM sink | sdk-go, sensor, helm | M | T6–T11 |
| | Sensor gateway as `SERVER_ROLE=sensor-gateway` with the `openctem_sensor_gw` DB role, Redis ACL user and Caddy sensor upstream/hostname; command-bound results enforced in the gateway; sealing moved to the core | api, gateway, helm | L | T3, T4 |
| **P2 — people and data** | Two-person rule for widening (API-recorded approvals) and the signer's ledger. **Built** (§11.5): the ledger in the signer's state, the scope service's hook, the approval rule of RFC-054 §7/§12 checked by the signer, sign-time enforcement, detection A10 | api, web | M | T6, T7 |
| | Credential references with Vault and CyberArk providers on the sensor | api, sdk-go, sensor, web | M | T8, T9 credentials |
| | Ingest worker as a separate sandboxed process; string normaliser; per-field caps; URL validation | api | M | T3, T5 |
| | Detections A1–A12 | api | M | all, detection |
| | Keyed audit checkpoints (HMAC key held by the signer, or periodic signer-signed chain heads exported to the SIEM) | api, signer | S–M | T8 |
| | Staged rollout rings and the customer deploy window for templates, settings and content (§5.12); signed scope documents checked by the sensor next to the job envelope (§5.6, Uptane two-repository) | api, sdk-go, sensor, web | M | T7–T10, bad content |
| | The RFC-034 forwarder for every job of a proxy-aware tool; `policy render` for nftables/iptables/NetworkPolicy | sdk-go, sensor | M | T6–T10 |
| **P3 — stronger keys** | WebAuthn-bound approvals verified by the signer; K2 (KMS/HSM); tenant template-signing key; separate `cmd/sensor-gateway` binary; RLS on the gateway role | api, web, signer | L | T7, T9, T10 |
| | RFC-031 Part B (verified self-update, no downgrade) and content anti-rollback against platform pins | sensor, sdk-go | M | T12, content downgrade |
| **P4 — optional topologies** | Gateway relay mode / external broker (§5.5); TPM-held keys and optional mTLS on the sensor hostname (RFC-032 P5) | api, sdk-go, helm | L | deployment |

**Ranking.** P0 first: every item is small, needs no protocol change, and
together they close the five ranked risks' cheapest paths (the member
command bypass, unbound writes, unsigned templates on the sensor, unaudited
widening, missing hardening defaults). RFC-032 P1–P2 is the P0 dependency
that P1 builds on. P1 is the core of mutual distrust (signer, local policy,
gateway): after it, neither a database writer nor an API compromise can
direct a sensor outside the owner's policy, and a sensor no longer shares a
process with the admin API. P2 adds the human control (two-person widening)
and the data-path isolation. P3 and P4 harden keys and topology for the
installations that need them.

### 6.1 P0 work breakdown

P0 ships as four independent PR groups, each owned by its own
implementation work, each verified end to end before it merges. RFC-032
P1–P2 runs in parallel as the P0 dependency.

| Group | Repos | Contents | Status (2026-10-04) |
|---|---|---|---|
| **(A) API authorization and scope** | api | Q5 (c): `scan` commands through `POST /api/v1/commands` run the scan target resolution (exclusions, zone routing, private-address check) **and** are owner/admin only; `UpdateScan` runs the config validator; the ingest worker re-reads the sensor's status before processing a queued report, and revoking a sensor re-queues its leased commands; audit events for scope targets, exclusions, tools and scanner templates, and the widening alert (A7); length caps on sensor-supplied text fields (title, description, message, remediation, references) | Merged: #877 (`scan` commands admin-only and scope-checked), #882 (worker drops queued reports of revoked sensors), #902 (revoke takes back leased commands), #885 (scope, tool and template audit), #886 (text caps) |
| **(B) Output encoding** | web, api | `sanitizeExternalUrl` (`safeHref`) on every data-driven `href`/`src` plus an ESLint rule; markdown sanitiser refuses `//host`; CSP `img-src` narrowed and a plan for script nonces; Jira descriptions escaped for wiki markup; server CSV skips leading whitespace like the client | Merged: #884 (encoded links and images, nonce-based CSP), #887 (scanner text encoded in tickets and notifications) |
| **(C) Result binding and quarantine** | api (+ sdk-go for the command id on v1 where needed) | Q6 (a): unsolicited reports only from collector/CI roles, stored in a quarantine state that never auto-resolves; tenant switch `sensor_results_require_command` (on for new tenants); advisory validation evidence off by default; scan sessions and ingest-job status scoped to the sensor; sensor reports never change compliance, classification, PII/PHI or exposure flags of an existing asset and never reactivate archived assets; auto-reopen and auto-resolve only from command-bound reports of the same tool; legacy "no tools declared" auto-resolve off | Merged: #889 (migration `000317`). The switch shipped as the result policy `warn`/`quarantine` (§5.3 note). Follow-ups: console review page, sdk-go sending the command id on the v1 fallback, S3e/S3f binding |
| **(D) Sensor-local gates** | sdk-go, sensor, helm-charts, snippets | Q3 (a) / Q4 (a): the policy file loader with the P0 subset (`targets.allow/deny`, `ports.allow`, `templates.custom`, `interactsh`, `kill_switch_file`), `SENSOR_ALLOWED_RANGES` / `SENSOR_ALLOWED_PORTS` shorthands in `ScanTargetPolicy`; custom templates and `allow_interactsh` opt-in (off for new installs, existing installs warned); `no_local_policy` health flag and the tenant switch to refuse private targets without a policy; a cap on `timeout_seconds`; hardening defaults (`runAsNonRoot`, read-only root, `cap_drop`, seccomp) in snippets and the chart | Platform side merged: #916 (reported policy, refusals, private-target switch, hardened snippets). sdk-go#140 and sensor#119 merged on `main` after sensor v0.8.0: needs the next sensor release |

## 7. Compatibility

| What | Behaviour |
|---|---|
| Sensors on old SDKs (`rda_` / `octs_` bearer keys, v1) | unchanged until the tenant raises a switch or the bearer-key sunset; they never receive sealed credentials, never pin a root, and their reports without a command go to quarantine once the tenant enables `sensor_results_require_command` |
| New SDK, platform without a signer | jobs accepted on the authenticated channel with a `jobs_unsigned` health flag; the local policy still applies in full |
| New SDK with a pinned root | refuses unsigned jobs; the platform never sends it one |
| Single-container installs | `SERVER_ROLE=all`, signer as an optional second container; the all-in-one image can supervise the signer as a separate process with its own user and key file |
| Platform rollback below the signer release | sensors with a pinned root refuse the old platform's unsigned jobs (fail closed, visible); operators roll forward or set `require_signed_jobs: false` locally |
| Bearer-key sunset | decided 2026-10-03: every bearer sensor key (`rda_`, `octs_`) is retired **90 days after RFC-032 P1–P2 ship** (no longer fixed at 2027-04-01); existing `rda_` sensors move to `octs_` on auto-renew before that. At the sunset, key-bound identity, command-bound results and (for sensors on the new SDK) signed jobs become the floor |

## 8. Alternatives considered

| Alternative | Why not |
|---|---|
| Sign jobs in the API process with a key from the environment | The API process is exactly what we must not trust; an RCE reads the key. Better than nothing (stops DB-only and path attackers), so it is the fallback if the signer slips, never the target |
| Rely on mTLS only | Authenticates the channel, not the job; a compromised API still sends valid jobs over valid mTLS |
| Platform-side scope checks only | Already exist (routing, zones, ownership gate); they are code in the process we must not trust |
| Local policy only, no signing | Protects the network owner, but not the tenant against a path attacker or a DB writer inside the owner's allowed ranges; both are needed |
| Separate microservice per sensor route | More moving parts with no security gain over one gateway with one role |
| Store credentials on the platform, sealed (T2) as the default | Concentrates every tenant's credentials in the most exposed component; kept as an option for tenants without a vault |
| Full TUF repository for jobs | Jobs are per-sensor, short-lived and many; TUF fits the key set and content, a DSSE envelope with `seq`/`nonce`/expiry fits jobs (Uptane's Director uses the same split) |

## 9. Decisions

**Approved 2026-10-03:** every recommendation below was accepted:
Q1 (a), Q2 (a), Q3 (a), Q4 (a), Q5 (c), Q6 (a), Q7 (a), Q8 (a).

| # | Question | Options | Recommended |
|---|---|---|---|
| Q1 | Who signs jobs | (a) a separate signer service with its own key (K1 by default, K2 optional), offline root; (b) the API with a key from the environment; (c) KMS/HSM only | **(a)**; (b) only as a stop-gap if P1 slips; (c) as an option |
| Q2 | Two-person rule | (a) widening needs two approvers other than the requester, narrowing one; (b) every scope change needs two; (c) none | **(a)**, API-recorded in P2, WebAuthn-bound in P3 |
| Q3 | Sensor without a local policy file | (a) works as today, with a health flag and a tenant switch to refuse private targets; (b) refuses every job | **(a)**; new installs ship a policy template from the install dialog |
| Q4 | Custom templates and `allow_interactsh` on sensors | (a) local opt-in, off for new installs, existing installs keep their behaviour with a warning until they set it; (b) off everywhere at once | **(a)** |
| Q5 | `POST /api/v1/commands` for `scan` | (a) run the scan target resolution (exclusions, zone, private check) and keep it for members; (b) owner/admin only; (c) both | **(c)** |
| Q6 | Results with no command | (a) quarantine (stored, never auto-resolves, reviewable), and only for collector/CI roles; (b) refuse | **(a)** |
| Q7 | Gateway shape first | (a) a server role of the same binary, then a separate binary; (b) a separate binary first | **(a)** |
| Q8 | Credentials default for authenticated scans | (a) references to a sensor-local vault (T1); (b) platform-held, sealed (T2) | **(a)**, T2 remains an option (RFC-032 E10) |

## 10. Sources

- RFC 9421 HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421.html
- RFC 9180 HPKE: https://www.rfc-editor.org/rfc/rfc9180.html
- DSSE: https://github.com/secure-systems-lab/dsse
- The Update Framework specification: https://theupdateframework.github.io/specification/latest/
- Uptane standard (Director/Image repositories): https://uptane.org/docs/latest/standard/uptane-standard
- go-tuf v2: https://github.com/theupdateframework/go-tuf
- Nuclei template signing and CVE-2024-43405: https://github.com/projectdiscovery/nuclei/security/advisories/GHSA-7h5p-mmpp-hgmm
- OWASP API Security Top 10 2023, API1 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
- HashiCorp Vault AppRole: https://developer.hashicorp.com/vault/docs/auth/approle
- CyberArk Central Credential Provider: https://docs.cyberark.com/credential-providers/latest/en/content/ccp/ccp-intro.htm
- Trojan Source (bidi overrides): https://trojansource.codes/
- OWASP CSV injection: https://owasp.org/www-community/attacks/CSV_Injection
- CVE-2024-1709: https://nvd.nist.gov/vuln/detail/CVE-2024-1709
- TUF security: https://theupdateframework.io/docs/security/
- Vault Transit: https://developer.hashicorp.com/vault/docs/secrets/transit
- AWS KMS asymmetric key specs (Ed25519): https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html

## 11. Amendment (2026-10-08): sensor → platform input review and the outbound-only invariant

Since the RFC was accepted, the platform has started accepting more from sensors:

- protocol v3 (gRPC over mTLS with SNI passthrough, an HTTPS binding, a control stream, Redis wake fan-out);
- manifests with content digests, transport and fallback reasons;
- sandbox provenance, and command logs;
- CI uploads over OIDC.

This amendment records the review of every sensor → platform input on `develop` (6684c011b), with sdk-go `main` (2e008ba) and sensor `main` (31394db). It sets the outbound-only rule as an invariant and revises decision Q3 for new installs. The review's evidence is in [architecture/sensor-platform-trust.md](../architecture/sensor-platform-trust.md#sensor--platform-input-review-2026-10-08).

### 11.1 Invariant: sensors are outbound-only

> **Sensors never accept inbound connections. All control flows over the sensor-initiated, authenticated
> channel** (poll and claim, the v3 control stream, pairing). The sensor binds nothing reachable from the
> network. Health, metrics and diagnostics stay on loopback or a Unix socket, or travel over that channel.

| Concern | Sensor-initiated (kept) | Platform-initiated (rejected) |
|---|---|---|
| Firewall and NAT | Works behind NAT, egress proxies and default-deny inbound firewalls. The network owner opens only one outbound flow to the gateway. | Every sensor host needs an inbound port, a firewall exception and often a public address. Each sensor is then a listener on the internet or the LAN. |
| SaaS blast radius | A platform compromise reaches only sensors that are connected, and only through messages they validate. No platform component holds a list of addresses it can dial into. | The platform holds addresses and credentials for every tenant's sensor network. A platform compromise can then dial into every customer network at once. |
| Compromised-platform containment | The sensor decides what it accepts: signed jobs (§5.6), the local policy (§5.7), the kill switch. An attacker who controls the platform can only send what the sensor's checks admit. | A listener runs its parser on whatever arrives, before any of the sensor's own checks. A compromised platform, or anyone who can reach the port, attacks that parser directly. |
| Attack surface on the sensor host | None from the network. | A network service with its own authentication, TLS, parsing and DoS surface, on customer hardware the platform operator does not patch. |
| Identity | The sensor proves its key on every request (RFC 9421, mTLS). The platform authenticates the sensor. | The platform would need a credential that every sensor accepts. One stolen platform credential would open every sensor. |

**Verified 2026-10-08:**

- The sensor binary has no `net.Listen`, `ListenAndServe`, `grpc.NewServer`, pprof or `DefaultServeMux` server on its path.
- Per-task relays bind to 127.0.0.1 inside a private network namespace.
- Forwarder sockets are Unix sockets.
- No image has an `EXPOSE`.
- A latent webhook collector (default `:8080`) is never started, and is to be removed.

**Enforced by:**

- a regression test in the sensor repository: a static guard over the build's packages, plus a runtime check that the process holds no listening socket;
- a container smoke check: no exposed ports and no LISTEN sockets.

A future diagnostic surface must be added as a message on the existing channel, never as a listener.

### 11.2 What the review found, and what changed

No cross-tenant path was found:

- Every sensor-plane query takes the tenant and the sensor from the authenticated identity: a bearer key, an RFC 9421 signature, or an mTLS certificate re-checked against the key row on every request.
- No path parameter or body field can name another tenant.
- Results are bound to a command the sensor holds.
- Platform sensors cannot ingest into another tenant.

The defects were in availability, integrity inside a tenant, and the platform → sensor direction.

| # | Severity | Finding | Change |
|---|---|---|---|
| C1 | Critical | Result segments and CI uploads were fully decoded before their item limits were checked. A 1.2 MB body allocated 1.75 GB, enough for one sensor to OOM a shared replica. | The streaming pre-pass counts items before anything is decoded (`JSONBounds`). Over a bound the answer is `413 report-too-large`, and the SDK re-splits the segment (#1553). |
| H1 | High | The v3 HTTPS binding is mounted ahead of the router. It skipped the per-IP rate limit, the concurrency limit and the timeout, while an unauthenticated forged signature cost a database lookup. | The per-IP limit is kept. At most 256 unary calls per replica are in flight before authentication. Stream deadlines are lifted only after authentication. The gRPC binding gets a unary read deadline. Key-use writes are debounced (#1557). |
| H2 | High | Coverage auto-resolve closed findings on any asset a report named, not only on the assets the command covers. | Candidate assets are filtered through the command's targets (#1551). |
| H3 | High | The unauthenticated pairing rate limiter used the raw path segment as its key, about 1 MB each, held for 30 minutes. | Non-ids get a 404 before the limiter, which now keys on the parsed id (#1559). |
| H4 | High | Ingest staging was never purged, so an open → fill → abandon loop could fill the database disk. | A purge runs every 10 minutes, and the report header is capped (#1561). |
| H5 | High | A compromised platform or a TLS MITM can direct unpinned sensors that have no local policy. Jobs are unsigned (§5.6 not built). With no policy file a sensor accepts any target outside the built-in deny list. Platform TLS trusts the system roots unless `SENSOR_CA_FINGERPRINT` is set. The v3 CA pin is fetched over that channel and falls back on x509 errors. | Decisions in §11.4. sdk-go changes are stacked one PR at a time. |
| H6 | High | `SENSOR_SANDBOX_NETWORK=auto` silently runs tools unconfined under Docker's default seccomp. Targets are resolved once at admission and tools resolve again, so DNS rebinding reaches the sensor host's metadata or loopback. | Decisions in §11.4. |
| M1 | Medium | Scan-zone preview resolved any name with the platform's resolver and returned private answers. | The act-scope check runs before lookup. Only public or in-zone answers are shown. `SCAN_ZONE_RESOLVER` defaults to a public resolver on self-service installs (#1564). |
| M3 | Medium | Jira comments carried finding titles as live wiki markup. | Comments are encoded like issues (#1562). |
| M4 | Medium | A scan name could inject YAML or Groovy into generated CI snippets. | Names are folded to one line (#1563). |

The remaining medium items:

- per-tenant row and byte quotas;
- a per-sensor in-flight bound and a connection cap on v3;
- a process-wide decoded-bytes budget and a tenant-fair global concurrency limit;
- manifest history pruning;
- a per-tenant control-plane budget;
- a sharded nonce store;
- IPv6 grouping for pairing;
- an expected-organization pin at pairing;
- the source-resolve tool rule;
- findings outside the command scope.

Each is tracked in [architecture/sensor-platform-trust.md](../architecture/sensor-platform-trust.md#sensor--platform-input-review-2026-10-08).

### 11.3 Design additions

1. **One ingest trust boundary.** Every sensor input passes the same layer, in this order, before domain code runs:
   1. **Validate**: media type, digest, bounded pre-pass, schema.
   2. **Normalise**: one string sanitiser with per-field caps; URLs limited to http and https.
   3. **Bound**: per-segment, per-report, per-sensor and per-tenant quotas, plus a process-wide decoded-bytes budget.
   4. **Attribute**: tenant, sensor, command, tool and provenance come only from the identity and the stored command. Payload claims such as `discovery_source` are ignored, and timestamps are clamped.
   5. **Scope**: one rule decides create, change and close per asset, for assets, findings, relationships, coverage and source-resolve.
   6. **Quarantine**: anything out of scope, or above a poisoning heuristic, is quarantined, never applied silently.

2. **Trust level drives what a sensor may assert.**

   | Level | Who | Change existing | Close findings | Unsolicited push |
   |---|---|---|---|---|
   | T0 | bearer key, no policy, unpinned | nothing | nothing | quarantine only |
   | T1 | key-bound (paired) | assets its command covers | command-covered, same tool, blinding guard | collector role only |
   | T2 | key-bound + local policy + pinned + signed jobs | as T1 | as T1 | collector role only |
   | Platform sensor | operator-run | as T1, for the command's tenant only (the tenant comes from the job) | as T1 | never |

   Self-reported facts (tool lists, local policy state, `network_enforced`, transport) are for routing and display only. They never relax a platform check.

3. **Output encoding per renderer.**

   | Renderer | Rule |
   |---|---|
   | Web | React text only, `safeHref`/`safeImageSrc` for every data URL, nonce CSP |
   | CSV | leading-whitespace-aware formula escaping on every export |
   | HTML/PDF/email | `html/template` |
   | Jira (issue, epic, comment) | wiki escaping, URLs defanged |
   | GitHub/GitLab | code spans and blocks |
   | Slack/Teams | escaped, URLs defanged |
   | Telegram | HTML parse mode, escaped |
   | Generated configuration (CI files, install snippets) | one line, quoted per format |
   | Logs | structured, CR/LF quoted |

4. **Security signals** (closed-set labels only; per-sensor detail goes to the sensor timeline and audit log, not to metric labels):

   | Metric | Labels |
   |---|---|
   | `sensor_auth_failures_total` | `kind`: signature, replay, unknown_key, revoked, cert |
   | `sensor_cross_tenant_attempts_total` | `route` |
   | `sensor_quota_refusals_total` | `kind` |
   | `sensor_results_outside_scope_total` | `kind` |
   | `sensor_unsafe_posture` (gauge) | `kind`: policy_none, pin_none, network_unenforced, bearer_key |

   Alerts:

   | Alert | Fires when |
   |---|---|
   | `SensorAuthFailureSpike` | auth failures rise sharply |
   | `SensorQuotaPressure` | quota refusals rise |
   | `SensorPoisoningSuspected` | results outside scope pass a ratio threshold |
   | `SensorsUnhardened` | unhardened sensors persist for 24 h |

   These extend detections A1–A12 (§5.11).

### 11.4 Decisions (2026-10-08)

| # | Question | Decision |
|---|---|---|
| Q9 | Outbound-only | **Invariant** (§11.1), with a regression test in the sensor. |
| Q3 (revised) | Sensor without a local policy file | **New installs fail closed**: network jobs are refused with `no_local_policy` and a clear reason, and custom templates and out-of-band callbacks are refused. Existing paired sensors keep working and report `policy=none`. The Sensors page and an alert flag them, with a one-click "generate policy" built from the organization's scope. Q3 (a) stays for existing installs only, as an upgrade path. |
| Q10 | Platform TLS identity on the sensor | **Pinned at pairing.** The CA/SPKI fingerprint is stored in the identity and emitted in every install snippet. The v3 CA bundle is fetched only over the pinned channel and is sticky. An x509 failure never falls back to another binding. Unpinned sensors report `pin=none` and are flagged. |
| Q11 | Job signing | **Build §5.6 now** with a signer key separate from the API. It is never derived from `APP_ENCRYPTION_KEY`. Template signing moves to the signer. The sensor verifies before execution, and new enrollments require signed jobs. Platform side built (signer process, K1 custody, claim-time envelopes, off by default): [job-signing.md](../architecture/job-signing.md); sdk-go verifies (sdk-go#226); the offline root and the expiring, versioned key set are built (P1.5); the signer's scope ledger is built (§11.5). |
| Q12 | Unconfined sandbox | `auto` must not run unconfined silently. `network_enforced=false` is reported prominently: on the manifest, as a Sensors page warning and as an alert. Compose and Helm ship the seccomp profile by default. The forwarder re-checks every resolved address at connect time, refusing link-local, loopback and private ranges unless the zone or policy allows them. When unconfined, custom templates are refused and nuclei runs with local-network access restricted. |

### 11.5 The signer's scope ledger (P2, 2026-10-09)

§5.6 points 4 and 5, built as the first part of P2. Format, ceremony and
operation: [job-signing.md, "Scope ledger"](../architecture/job-signing.md#scope-ledger).

**What it is.** Per organization, the scope entries in effect (type,
pattern, tier ceiling, expiry) and the target exclusions, kept in the
signer's state directory (`ledger.log`, hash-chained like the signing log;
the ledger is its replay). The application database is never read. At sign
time every target must be covered by an unexpired entry at the tool's tier
(`stage.ProbeTier`, compiled into the signer) and not excluded; otherwise
the signer refuses (`out_of_ledger`, `tier_exceeds_ledger`,
`target_excluded`), the API fails the command with `SIGNER_REFUSED`, and
detection A10 (`SignerOutOfLedger`) fires. Matching is the API's own
(`pkg/domain/scope`: `*.x` covers `x`, CIDR containment, exclusions win);
passive tools and internal targets need no entry, as in RFC-054 §4.2.

**How it changes.** Only three ways: the scope service's `apply` (one hook,
`commitEntry`/`commitExclusion`; a widening is accepted by the signer
before it is saved, a narrowing is saved first and never blocked), a
periodic `sync` from the database that can only narrow, and the operator's
`openctem-signer ledger import` (signer stopped; into a non-empty ledger
only with `-replace`). The signer classifies each change itself; the
caller does not label it.

**Approvals (amends point 5).** The approval count is the organization's
policy as RFC-054 §7 and §12 decide it (`scope.Service`: 0, 1 or 2,
never 0 for t2, the sole-owner self-approval of A2), not a fixed "two
people": point 5's two-person rule is RFC-054 S3's setting. The signer
checks the rule again on what the API recorded: distinct approvers, the
requester's own approval never counts (a self-approval under A2 counts
once), at least one for a t2 entry, and an operator floor
`SIGNER_LEDGER_MIN_APPROVALS` (0 to 2) that no tenant setting lowers.
Narrowing needs no approval. There is no second approver model and no
tenant switch.

**Modes.** `SIGNER_LEDGER=enforce|audit|off`. Unset: `enforce` for a new
installation, `audit` (sign, record `ledger_audit`, warn) for one whose
signer signed before the ledger existed, `enforce` after an import. This
mirrors Q3 revised: new installs fail closed, existing ones get an upgrade
path (the export/import ceremony).

**Custom templates (§5.8).** A template version is approved for sensors
like a scope widening (the same policy count and rule, never its author)
and recorded in the ledger by digest; the job statement lists the digests
of the job's custom templates (`templates`), the signer refuses any it did
not record (`template_not_in_ledger`), and a sensor that verifies signed
jobs trusts the templates through the envelope. The per-tenant template
key the API derives remains only for sensors without signed jobs and is
removed once signed jobs are required.

**Residual risk until P3.** Approvals are as the API recorded them: an
attacker in the API process can claim approvals and widen (recorded in the
ledger log; bounded by the operator floor). The ledger still stops a
database writer (T8), every path that bypasses the scope service, and every
job outside approved scope (T9 can only run what people approved, or what
it can make look approved). Internal names and private addresses are left
to zones and the sensor-local policy. P3: approvals as WebAuthn assertions
over the change digest verified by the signer; the signed scope document
checked by the sensor next to the job (two repositories); zone ranges, time
windows and distinct-target ceilings in the ledger.
