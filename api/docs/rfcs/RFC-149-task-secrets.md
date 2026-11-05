# RFC-149: Task secrets

| | |
|---|---|
| Status | Implemented (2026-11-05): the platform side; the sensor SDK side ships in the same release |
| Scope | api (claim-time refs, sealed fetch, provider key storage, scan settings), contract (`secretref`), sdk-go and sensor (delivery to tools) |
| Architecture | [task-secrets.md](../architecture/task-secrets.md) |
| Related | RFC-034 (sensor network egress), [sensor-proxies.md](../architecture/sensor-proxies.md), [job-signing.md](../architecture/job-signing.md), RFC-052 (key-bound sensors), RFC-116 (sealed envelope) |

## 1. Problem

Tools a sensor runs need secrets: keys of third-party data services (passive
subdomain sources), the credentials of the proxy pool a job's traffic goes
through, and later the organization's own credentials for authenticated
scans. Before this RFC each kind had its own delivery path with its own lease
check, and they had drifted apart: the proxy credential route checked no
grant (an untrusted sensor received pool passwords) and resolved the
sensor's current pool rather than the job's; values crossed TLS terminators
and request logs in clear; the lease epoch travelled in a header the request
signature does not cover; credentials typed into a scan's settings were
stored and copied into every command; stored keys were not bound to their
row.

## 2. Decisions

1. **One endpoint for every kind**, `POST /api/v2/sensor/commands/{id}/secrets`.
   The proxy credential route is removed in the same release, without an
   alias; the per-tool key route never ships.
2. **The signed job lists the refs.** At claim the platform adds the payload
   member `secrets` (contract `secretref.Set`: id, kind, class, ref, slot,
   audience, consumer, required, local policy) before the job is signed, and
   records it per claim (`command_secret_grants`). The fetch answers only
   recorded refs, only to the lease holder. Names only, never values.
3. **Values are pulled per task**, so disabling, rotating or removing a value
   applies to the next task.
4. **The answer is sealed** with HPKE (RFC 9180; ML-KEM-768+X25519,
   HKDF-SHA256, ChaCha20-Poly1305) to a single-use key the sensor puts in its
   RFC 9421-signed request; the info binds sensor, command, lease epoch and
   the request body. Only key-bound sensors are answered.
5. **The lease epoch is in the signed body**, here and on the egress report.
6. **Class is the top dimension**: `provider` (a data service's key, the
   job's pool) and `target` (the organization's own systems). The fetch
   applies a class switch; target kinds come later and only add the kind.
7. **Trust for every kind**: an untrusted grant gets nothing.
8. **Shared sensors** get each held job's tenant values only, never the
   operator's local values (`local: never`), and only when fully confined.
9. **Bounded fetches**: `max_fetches` = tasks the job can produce + 2, at
   least 3, at most 256; every refusal is command-not-found; deliveries and
   refusals are audited without values.
10. **Stored keys are bound** to their row: the ciphertext embeds
    `{v, tid, source}` and opens only for that tenant and provider.
11. **The provider registry is the contract's** (`secretref/providers.json`),
    used for save validation on the platform and for the delivered-value
    check and the network audience on the sensor.
12. **Scan settings never carry credentials**: certain credentials are
    refused on save and block a run at trigger (`SCANNER_CONFIG_SECRET`);
    random-looking values stay warnings.

## 3. Wire

See the architecture document. The body is `secretref.FetchRequest`; the
answer `secretref.SealedAnswer` with content type
`application/vnd.openctem.secrets+sealed` and `Cache-Control: no-store`; the
plaintext `secretref.Answer`. A cross-implementation test vector
(`pkg/sensorproto/sealed/testdata/task-secrets-vector-v1.json`) is opened by
both the platform and the SDK.

## 4. Not built

- Provider-key scope introspection: a provider key that also opens
  organization data (a code host token with repository or admin scopes)
  should be refused or warned at save by calling the provider's scope
  introspection where one exists. Later work; today keys are expected to be
  low-privilege.
- Target credential kinds (`http_auth` first), the secret store as their
  storage, a tenant setting for target credentials on shared sensors.
- Removing credentials already stored in scan settings and in the payload of
  finished commands (existing rows are not rewritten by this change).
- A signature on the sealed answer, per-tenant data keys, usage reports and
  quotas, platform-held keys.

## 5. Security tests

`internal/infra/http/routes/secrets_db_test.go` (tenant isolation, lease,
sensor class, refs and count, rotation, storage binding, sealing, audit and
logs), `internal/app/tasksecret/service_test.go` (class gate, confinement,
bounds, body parsing), `pkg/sensorproto/sealed/reply_test.go` (vector and
binding), `tests/integration/scanner_config_secret_test.go`.
