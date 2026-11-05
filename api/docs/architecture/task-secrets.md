# Task secrets

How a secret reaches a tool that a sensor runs for the platform: one model
for every kind of secret. Design record: [RFC-149](../rfcs/RFC-149-task-secrets.md).
Contract: `github.com/openctemio/contract/secretref` (shared with the sensor
SDK; both sides validate with the same code).

## Two classes of secret

The class is decided by what a value opens, not by the vendor or the tool. A
code host token used to search public data is a provider secret; the same kind
of token used to clone the organization's repositories is a target credential.

| | **provider** (built) | **target** (gate built, no kind yet) |
|---|---|---|
| Opens | a third-party data service a tool consults (passive DNS, search, intel), or the proxy pool the job's traffic goes through | the organization's own systems (a web login, an API, SSH, a registry, a cloud account) |
| Kinds | `provider_key`, `egress_proxy` | `http_auth` and others, later |
| Chosen | automatically: the tool's provider slots; the job's pool | by a person, per scan, step or asset |
| Where it may be sent | the provider's registry hosts; the pool's endpoints (forwarder only) | the task's own targets within the credential's asset binding |
| Gate at fetch | trusted grant | trusted grant, the grant's credentials dimension, and an organization sensor (a shared sensor is refused until an organization can allow a named one) |
| Local values | the organization's value wins; the sensor operator's local value only on the organization's own sensor (`local: allow`); never on a shared sensor | later |
| Storage | `tool_source_keys`; `proxy_endpoints` | the secret store `credentials`, later |

## Flow

1. **Claim.** When a sensor claims a scan, retest, validate or proxy test
   job, the platform adds the payload member `secrets` (a `secretref.Set`)
   before the job is signed, so the job signature covers it
   (`internal/app/command/task_secrets.go`, `internal/app/tasksecret`):
   - `local`: `allow` on the organization's own sensor, `never` on a shared
     sensor;
   - one `provider_key` ref per **enabled** organization key of a provider
     the job's tool queries (`k1`..`kN` in provider id order; slot = ref =
     provider id; audience `provider:<id>`);
   - one `egress_proxy` ref `p1` (`required`, `local: never`, consumer the
     forwarder) when the job's egress member names a pool with an endpoint
     that needs credentials, or for a proxy test, its own pool when it has
     one. A shared sensor never gets an organization pool.
   The member belongs to the platform: one a command's creator put in the
   payload is replaced (or removed on every other command). The refs are
   recorded in `command_secret_grants` for the claim (command, lease epoch,
   sensor) with `max_fetches`. A claim whose grant cannot be recorded is
   handed back.
2. **Fetch, per task.** `POST /api/v2/sensor/commands/{command_id}/secrets`
   (v2 HTTPS only; protocol v3 does not carry it). The body is a
   `secretref.FetchRequest`: `lease_epoch`, `task` (audit only), `refs`, and
   `reply_key`, the base64url public half of a single-use HPKE key pair the
   sensor makes for this request. The request must be RFC 9421-signed by the
   sensor's key-bound identity, so the reply key and the lease epoch are the
   sensor's own.
3. **Answer.** `200`, `Content-Type: application/vnd.openctem.secrets+sealed`,
   `Cache-Control: no-store`, body `{"suite":1,"key_id","sealed"}`: the
   `secretref.Answer` JSON sealed with HPKE (base mode, single shot, KEM
   ML-KEM-768+X25519, HKDF-SHA256, ChaCha20-Poly1305;
   `pkg/sensorproto/sealed.SealToKey`) to the reply key, with
   `info = secretref.Info(sensor id, command id, lease epoch, SHA-256 of the
   exact request body)` and no additional data. A TLS terminator, a request
   log or a replayed request never holds a value, and an answer moved to
   another sensor, command, epoch or request does not open. The answer lists
   values and, for refs without one, a reason: `disabled`, `not_set`,
   `undecryptable`.

## Gates of the fetch

Every refusal is the same `404 command-not-found` problem; nothing tells a
missing command from another tenant's, a lost lease or an exhausted count.
In order (`internal/app/tasksecret/service.go`, `Fetch`):

1. a signed request of a key-bound sensor (a bearer-key request is refused);
2. a strict, valid body (`FetchRequest.Validate`, no unknown members, a reply
   key of the suite's KEM);
3. the command read in its own tenant: an organization sensor's tenant, or
   the shared job a shared sensor holds; nothing the sensor sends names a
   tenant;
4. held by this sensor, under the body's lease epoch (a header is never
   read), acknowledged or running;
5. a shared sensor must be confined: it reports `net.confined@1` and its
   manifest posture says the sandbox is required, in use and enforces the
   network;
6. the sensor's grant is trusted, for **every** kind (an untrusted grant gets
   no provider key and no proxy credential);
7. the claim's recorded grant exists for this sensor; every asked ref is in
   it; the class gate holds (above);
8. the fetch count is below `max_fetches`, counted atomically.

`max_fetches` is the number of tasks the job can produce (its targets; 1 for
a proxy test) plus 2 (the forwarder's fetch and one retry), at least 3 and at
most 256.

Values are read at fetch, so a key disabled, rotated or removed after the
claim is answered as it is now. Proxy credentials are those of the recorded
pool (never the sensor's current pool): the endpoints that may carry traffic
now, none for a disabled pool; a proxy test gets every endpoint of its pool
with credentials. A stored value that no longer meets its kind's rules is not
sent.

Audit: every answer is a `secret.delivered` event (sensor, command, task,
ref ids, kinds, classes, delivered and missing refs, provenance); every
refusal of an authenticated sensor whose tenant is known is a
`secret.refused` event with the reason. Neither ever holds a value or the
reply key. A delivered provider key's `last_used_at` is updated.

## Storage binding

`tool_source_keys.key_enc` is `Encrypt(json{"v":1,"tid":<tenant>,
"source":<provider>,"value":<key>})` under `APP_ENCRYPTION_KEY`. The value
opens only when `v`, `tid` and `source` match the row: a ciphertext copied to
another tenant's row or another source's row is `undecryptable` there (an
attacker who can write rows but holds no key cannot move a key). Proxy
endpoint credentials are bound the same way (`{t, e}`). The binding survives
`rekey`, which re-encrypts opaque strings.

## Provider keys (console)

The registry of providers is the contract's (`secretref/providers.json`):
id, display name, format (`key`, or a `pair` such as `TOKEN:ORG_ID`), the
hosts the key may be sent to, the tools that use it, and for keys that name
their endpoint the rule that host must meet. `pkg/domain/toolsource` maps the
contract's refusals to the platform's error codes.

| Route | Permission |
|---|---|
| `GET /api/v1/tool-sources` | `scans:secret_store:read` |
| `PUT /api/v1/tool-sources/{source}/key` `{value}` (set or replace) | `scans:secret_store:write`, owner/admin, step-up, credential factor |
| `PATCH /api/v1/tool-sources/{source}` `{enabled}` | `scans:secret_store:write`, owner/admin, step-up, credential factor |
| `DELETE /api/v1/tool-sources/{source}/key` | `scans:secret_store:delete`, owner/admin, step-up |

A key is 1 to 1024 visible ASCII characters without spaces, with a secret part
of at least 8; a key whose first part names where the tool connects (intelx
and zoomeye `HOST:KEY`, redhuntlabs `https://HOST/PATH:KEY`) is accepted only
for the provider's own service. No answer carries a key (the last four
characters of the secret part at most). Changes are audited
(`tool_source_key.set`, `.enabled`, `.disabled`, `.deleted`).

## Scan settings never carry secrets

A credential typed into a scan's `scanner_config` is refused on create,
update and clone (`SCANNER_CONFIG_SECRET`, naming the keys, never the
values): a known credential format (bearer or basic header, private key
block, provider token, credentials in a URL), or a value under a
credential-named key unless it is a plain mode word (`"auth": "basic"`).
Values that only look random are warned about (`scanner_config_warnings`),
never refused: identifiers and names reach that bar too. A scan stored with
a credential before the refusal is blocked at trigger with the same code, so
the value is never copied into a command. Existing rows are not rewritten.

## On the sensor (sdk-go)

Refs come only from the verified job payload. A required ref of an unknown
kind refuses the job (`secret_kind_unsupported`). Per task the tool host
fetches the refs whose slots the tool's manifest declares; the egress
forwarder fetches the pool ref once per job. Merge per slot: the platform's
value; else the local value if `local: allow`; never on a shared identity. A
fetch error is no platform value and no local fallback unless the signed
policy allows it. Values reach the tool through the run message or a
task-private file, never env or argv; the task's network scope is narrowed
to the audiences of what it received; every outbound stream of the task is
scrubbed for each value and its encodings.

## Threat model

| Threat | Control |
|---|---|
| Another tenant's sensor, or another sensor of the tenant | The command is read in its own tenant; lease holder under the signed epoch only; the grant row names the sensor |
| A lost or replayed lease | Epoch in the signed body; live command only; a new claim (new epoch) records new refs |
| A forged job asks for more | Refs are the platform's, recorded at claim; the fetch answers only those |
| Untrusted or new sensor | Nothing, for every kind |
| Bearer-key sensor | Nothing: its reply key would not be authenticated |
| Shared sensor serving many tenants | Each held job's tenant only; confined sensors only; `local: never`; no organization pool |
| TLS terminator, proxy, request log | Answer sealed to a single-use key; request bodies carry no value; `no-store` |
| Replay of a fetch | Single-use nonce; a replayed body yields ciphertext only the original reply key opens; bounded count |
| Database write without the key | Ciphertext bound to tenant and source |
| Secrets in the job, payload, audit or logs | Names only in the job; audit and logs never hold a value; scan settings refuse credentials |
| A provider key that also opens organization data (a code host token with repository or admin scopes) | Not built: provider-key scope introspection at save is later work; use low-privilege keys |
