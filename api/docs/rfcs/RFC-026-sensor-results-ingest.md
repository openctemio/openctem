# RFC-026 — Sensor results ingest (protocol v2)

> Status: **Accepted; api iteration 1 implemented** (2026-10-01). The open
> questions of §10 are decided in §10.1; what shipped is in §7.6. The api
> serves v2 results (WP-A1…A7: api#635, #636, #638, #639, #640, #642 and the
> WP-A7 PR). sdk-go (WP-S1…S3), sensor (WP-G1) and the import API (WP-A8)
> follow. Operator view: `docs/architecture/sensors.md`.
> Scope: api + sdk-go + sensor (the `agent` repo), with a later import API
> in api + ui.
> Builds on: [RFC-023](RFC-023-scan-zones-and-scanners.md) (sensors, protocol
> v2, §4b P2/P9, §9.2 C1–C8, §10 C-2/C-3/C-4/C-6), and
> [RFC-005](RFC-005-asynchronous-ingest.md) (the async ingest queue this
> design reuses).
> Question from the product owner: *"Do we need separate APIs like
> /ingest/sarif, or one /ingest endpoint with the format (SARIF or anything
> else) set by a parameter in the body?"*

## 1. Decision

**Neither.** Format is not a parameter of the sensor protocol at all.

1. **Sensors speak one format.** Protocol v2 has one results resource per
   *data kind*, not per format. For scan results that kind is a CTIS report,
   and CTIS is the only format it accepts. SARIF, Nuclei, Trivy and the other
   tools are converted **in the SDK**, on the sensor.
2. **The format is declared by `Content-Type`, never by a body field.** The
   one accepted type is `application/vnd.openctem.ctis.v1+json`. Anything else
   gets `415` with an `Accept` header. A body field would mean parsing the
   body before knowing how to parse it.
3. **Results are a resource the sensor names.** The sensor sends
   `PUT /api/v2/sensor/results/{report_id}` (or the same under
   `/commands/{command_id}/`), where `report_id` is a UUID the sensor chooses.
   The URL is the idempotency key and `Content-Digest` is its fingerprint.
   Retries never duplicate; a different body under the same id gets `409`.
4. **Large reports are sent in segments, and every segment is a complete CTIS
   document** carrying the tool, the metadata and the assets its findings
   reference. A `commit` request closes the report, and only a committed
   report can auto-resolve findings. Byte-range uploads (tus, IETF resumable
   upload) are not used for sensors.
5. **Validation is complete before acceptance, then processing is async.** The
   edge pipeline runs in this order: authenticate, rate limit, check headers,
   read a bounded body, verify the digest, decompress with a bound, strict
   I-JSON decode, schema and semantic checks. The answer is then `202` with a
   `Location` status resource. A malformed report is refused whole (`4xx`, RFC
   9457 problem). Valid reports with bad *items* are accepted with per-item
   rejections on the status resource (partial success).
6. **Provenance is stamped by the server.** Tenant, sensor, role, trust tier,
   command, zone, protocol, receive time and digest are stamped by the server.
   No CTIS field can set them, and claims in the body (tool name,
   `metadata.id`, asset scope) are checked against them. There is no fallback
   asset: a finding with no resolvable asset is rejected.
7. **People and CI pipelines that hold a raw file use a different API.**
   `POST /api/v1/imports` is user-authenticated (`findings:import`), selects
   the format by `Content-Type` from a short allow-list, converts on the
   server inside a bounded (later sandboxed) converter, and feeds the **same**
   validation and queue as sensors.
8. **v1 stays frozen and served.** Its per-format routes are retired later
   with a dedicated **minimum ingest protocol** lever, measured per tenant.
   C7's job lever alone cannot do it, because collectors keep pushing.
9. **v2 ships before full request signing.** Iteration 1 authenticates with
   the existing sensor key plus a mandatory `Content-Digest`, on the same
   isolated sensor route group. RFC 9421 signatures are added per sensor
   later, without changing the contract.

## 2. Why this answers the question

| Option | What it means | Verdict |
|---|---|---|
| **A** One endpoint per format (v1 today) | `/ingest/sarif`, `/ingest/recon`, `/ingest/scan`, … | Rejected for sensors. Every format is a server parser exposed to every sensor key. The v1 bugs come from here: SARIF parse errors returned 500, SARIF with no asset was filed on a shared per-tool asset, and `/ingest/scan` auto-detects the format by sniffing. |
| **B** One endpoint, format in a body field | `{"format":"sarif","data":…}` (v1 `/ingest/scan` `scanner_type`) | Rejected. The body must be parsed before the parser is known, so it is two parsers per request, and rate limits, size limits and metrics cannot see the format before the body is read. It also invites base64 wrapping (v1 chunks), which grows the body by a third and hides it from compression. |
| **C** One endpoint, format by `Content-Type` | OTLP, Loki, Prometheus RW 2.0, CloudEvents binary mode | **The selector we use.** It is standard HTTP (RFC 9110 §8.3, §15.5.16), cheap to check before the body is read, and signable. On its own it still lets the server grow N parsers. |
| **D** One canonical format, conversion in the client | SARIF-only, CycloneDX-only or OCSF-only intake | **The sensor contract.** The smallest parser surface and one validation path. |
| **E** D for sensors + C for human/CI imports | — | **Recommended**, with the refinements in §1. |
| **F** Multi-item envelope | CloudEvents batch, generic bulk endpoints | Rejected for v2. It mixes data kinds in one request, so per-kind authorization (D21 push scopes), per-kind quotas and metrics move inside the body. Our kinds have different authorization. |

### 2.1 Scored comparison

Scores are 1 (poor) to 5 (best). Weights reflect that this is the main write
path for semi-trusted, sometimes third-party code (RFC-023 D22).

| Criterion (weight) | A per-format | B body field | C Content-Type | D canonical | **E = D + C import** | F envelope |
|---|---|---|---|---|---|---|
| Security: parser surface on sensor keys (×3) | 1 | 1 | 2 | 5 | **5** | 2 |
| Security: malicious-producer resilience (×3) | 2 | 2 | 2 | 4 | **4** | 3 |
| Security: signing compatibility (×2) | 4 (`@path`) | 4 (digest) | 4 (needs `content-type` covered) | 5 | **5** | 3 (item headers inside body) |
| Correctness: asset/provenance attribution (×3) | 2 | 2 | 2 | 5 | **5** | 3 |
| Correctness: dedup and idempotency (×2) | 2 | 2 | 3 | 4 | **5** (PUT + digest) | 3 |
| Operability: limits, rate limits, per-type metrics before parse (×2) | 4 | 1 | 5 | 5 | **5** | 2 |
| Operability: debugging (×1) | 3 | 2 | 4 | 4 | **4** | 2 |
| Evolvability: schema versions, deprecating formats (×2) | 2 | 3 | 4 | 4 | **5** | 3 |
| Client burden: SDK users (×1) | 4 | 4 | 4 | 4 | **4** | 3 |
| Client burden: non-Go third parties and CI with a raw file (×2) | 5 | 5 | 5 | 2 | **4** | 2 |
| Performance: streaming, large reports (×1) | 3 | 1 (base64) | 4 | 4 | **5** (segments) | 3 |
| **Weighted total (max 110)** | 59 | 52 | 72 | 94 | **103** | 58 |

D loses points only on the burden placed on someone who holds a raw SARIF
file and no SDK. E removes that by giving them a separate, user-authenticated
door that does not widen the sensor surface.

### 2.2 The three strongest pieces of evidence

1. **A platform with one data model accepts one format, async, and decides
   what the data means server-side from authenticated context.** SARIF-only,
   CycloneDX-only and OCSF-only intake APIs validate against the schema
   (`400` + RFC 9457), answer `202` with a processing status to poll, and
   leave conversion to the client.
2. **The many-parsers model has a measurable security cost.** Importers that
   select hundreds of parsers with a body parameter have public advisories
   for decompression bombs in individual parsers (the same class as our
   ingest-chunk zstd bomb, api#554), for imports that wrote into an asset or
   engagement the caller was not authorized for, for import errors that
   leaked another organization's name, and for uneven, per-parser XML
   hardening. Those are our three bug classes (bomb, mis-attribution, error
   leak), at scale.
3. **HTTP and telemetry practice selects the format with `Content-Type`, and
   signatures make it safe only if that header is signed.** OTLP/HTTP has one
   path per signal and picks protobuf or JSON by `Content-Type`
   ([OTLP](https://opentelemetry.io/docs/specs/otlp/)). Prometheus Remote
   Write 2.0 picks its message schema with
   `Content-Type: application/x-protobuf;proto=…` and answers `415` otherwise
   ([PRW 2.0](https://prometheus.io/docs/specs/prw/remote_write_spec_2_0/)).
   CloudEvents' binary mode is exactly "format by `Content-Type`", while its
   structured mode is "format inside the body"
   ([HTTP binding §3](https://github.com/cloudevents/spec/blob/main/cloudevents/bindings/http-protocol-binding.md)).
   RFC 9110 tells a `415` to list what is accepted
   ([§15.5.16](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.16)).
   RFC 9421 warns that any uncovered header "will change the processing of
   the message"
   ([§7.2.1](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.1)), and
   RFC 9530 names `Content-Type` tampering under a digest-only signature
   ([§6.3](https://www.rfc-editor.org/rfc/rfc9530.html#section-6.3)).

### 2.3 The preliminary proposal, tested

| Preliminary proposal | Verdict | Change |
|---|---|---|
| v2 accepts only CTIS | **Right** | Kept. |
| Conversion in the SDK | **Right, for the wrong main reason** | Client-side conversion shrinks the server's parser surface and gives each converter one owner. It does **not** make a sensor trustworthy: a malicious sensor sends arbitrary *valid* CTIS. The real defences against a malicious producer are semantic: tool gate, command binding, asset scope, no fallback asset, no writes to shared catalogs, auto-resolve only on commit (§5). |
| `POST /api/v2/sensor/results` | **Partly** | `PUT …/results/{report_id}`. The sensor-chosen id is the idempotency key and is covered by the signature via `@target-uri`. This avoids depending on the Idempotency-Key draft, which expired on 2026-04-18 ([draft-07](https://www.ietf.org/archive/id/draft-ietf-httpapi-idempotency-key-header-07.html)). |
| "plus chunks" | **Underspecified, and v1's chunk design is the bug** | v1 chunks are base64 in JSON, only the first carries the tool, and each is ingested as an independent report, so report-level steps (auto-resolve, completion) only ever see one part, and chunks after the first lose the tool context. v2 segments are complete CTIS documents plus a `commit` (§3.5). |
| Raw files go to a user-authenticated import API, format by `Content-Type` | **Right** | Added: context parameters (asset, repository/commit), a closed allow-list, a bounded converter, and the same downstream pipeline (§6). |
| Example type `application/vnd.openctem.ctis+json;version=1` | **Changed** | `application/vnd.openctem.ctis.v1+json`. RFC 6838 §4.3 says new parameters should not introduce new functionality (written for the standards tree; we follow it). Parameter syntax also has equivalent spellings (`version=1`, `version="1"`, `VERSION=1`), which is a canonicalisation differential between the signer and the router (RFC 9421 §7.5.2). A single token compares exactly. |
| "one endpoint" | **Refined** | One endpoint per **data kind**, the way OTLP has one per signal. Results (CTIS) are this RFC. Runtime telemetry and validation evidence keep their own resources under the same envelope rules. |
| v1 stays frozen | **Right** | Plus a measured retirement lever for ingest (§8.3). |

## 3. The v2 results contract

All paths are under `/api/v2/sensor`, in the sensor route group (sensor
credentials only; RFC-023 C-2).

### 3.1 Resources

| Method and path | Purpose | Success |
|---|---|---|
| `PUT /results/{report_id}` | A whole report in one request, committed implicitly. Unsolicited results (collectors, CI runners). | `202` first time; `200` on an identical replay |
| `PUT /commands/{command_id}/results/{report_id}` | The same, bound to a command the sensor claimed. | as above |
| `PUT /results/{report_id}/segments/{seq}` and the `/commands/{command_id}/…` form | One segment of a segmented report, `seq` = 0…n-1. | `202` / `200` replay |
| `POST /results/{report_id}/commit` (and command form) | Closes a segmented report: `{"segment_count": n, "segment_digests": ["sha-256=:…:", …]}`. | `202` |
| `GET /results/{report_id}` | Status resource (§3.7). | `200` |
| `DELETE /results/{report_id}` | Abandons an uncommitted segmented report. | `204` |

`report_id` is a UUID (RFC 9562; the SDK uses v7), lower-case, validated
strictly (`400` otherwise). It is unique per `(tenant, sensor)`. A
`command_id` must be a command assigned to this sensor and claimed by it,
and not yet expired or finished more than 15 minutes ago (RFC-023 C-8); any
other id is `404`, so the sensor learns nothing about other commands. All
segments and the commit of one report must use the same form (bound or
unsolicited) and the same `command_id`, otherwise `409`.

Why two path forms rather than a header: the command binding is part of the
resource identity, it is covered by `@target-uri` without a profile needing
to remember a header, and routing and authorization (load the command, check
the assignee) happen before the body is read.

### 3.2 Request headers

| Header | Rule |
|---|---|
| `Authorization` | Iteration 1: the sensor key, as in v1 (`Bearer rda_…` / `X-API-Key`). Iteration 2: RFC 9421 `Signature-Input` + `Signature` (§4). |
| `Content-Type` | Exactly `application/vnd.openctem.ctis.v1+json`, compared case-insensitively on type/subtype. No parameters except an optional `charset=utf-8`. Anything else is `415` with `Accept: application/vnd.openctem.ctis.v1+json`. `application/json` is refused, which keeps the door shut on sniffing. |
| `Content-Encoding` | Absent, `gzip` or `zstd`; one coding only. Anything else is `415` with `Accept-Encoding: gzip, zstd` (RFC 9110 §15.5.16). |
| `Content-Length` | Required; chunked transfer coding is refused with `411`. Larger than the limit is `413` before any byte is read. |
| `Content-Digest` | Required: `sha-256` (or `sha-512`) over the content **as sent**, i.e. over the compressed bytes (RFC 9530 §2). A missing or malformed header is `400 digest-required`; a mismatch is `400 digest-mismatch`. |
| `User-Agent` | `openctem-sdk-go/<ver> (<sensor-binary>/<ver>)`, recorded on the status resource; never trusted. |

The minor CTIS version travels in the body (`"version": "1.3"`). The major
version in the media type and the body's major must agree, otherwise `422
version-mismatch` (anti-differential: never "header says v1, body says
v2"). Minor versions are additive only: new optional fields, new enum
values. A server that does not know a newer minor's field answers `422`
naming it, and the SDK does not send fields newer than the server
advertises (RFC-023 C3).

### 3.3 Edge pipeline: parse once, completely, before acceptance

Order matters; each step is cheaper than the next and runs before it.

1. **Route + authenticate** the sensor (key, later signature). Unknown,
   disabled, revoked → `401` (generic text, RFC-023 conventions).
2. **Authorize the data kind**: the sensor's key scopes allow `results`
   (D21); platform sensors only on the command-bound form.
3. **Rate limit and concurrency**, per sensor and per tenant (existing
   `TelemetryRateLimiter` + `TenantConcurrencyLimiter`) → `429` +
   `Retry-After`. Queue backpressure (existing `maxPendingPerTenant`) →
   `429` + `Retry-After`.
4. **Header gates**: `Content-Type` (415), `Content-Encoding` (415),
   `Content-Length` (411/413), `Content-Digest` present (400), path ids
   well-formed (400), command bound and owned (404), report state allows
   this write (409).
5. **Read the body** through a reader capped at `Content-Length` ≤ limit,
   hashing as it reads. **Verify the digest** on the wire bytes. A forged or
   damaged body never reaches the decompressor.
6. **Decompress with a bound**: output cap, ratio cap, zstd window cap,
   decoder concurrency 1. Over the cap → `413 decompressed-too-large`.
7. **Strict decode** into `ctis.Report`: I-JSON (RFC 7493). Duplicate member
   names, invalid UTF-8, trailing data, depth > 64 and unknown fields are all
   `422`. Go's `encoding/json` silently keeps the last duplicate and replaces
   invalid UTF-8, which is the JSON parser-differential class (two parsers
   reading one body differently), so a token-level pre-pass enforces this. One parser: the Go
   decoder plus the existing validator. No second runtime JSON-Schema engine
   (a second parser is a second interpretation). Parity between the Go
   structs and `schemas/ctis/v1` is proven in CI instead, by a new test
   modelled on sdk-go's `ctis-parity` job (WP-A3).
8. **Structural validation** (whole-report): limits (§3.6), required fields,
   enum values, `metadata.id` empty or equal to `report_id`, `tool` present
   in every document. Failure → `422 schema-invalid` with `errors[]`
   (§3.8), and nothing is stored.
9. **Store and enqueue**: the decompressed, validated bytes go to
   `ingest_jobs` (RFC-005) with the provenance of §5. Answer `202`.

Semantic checks that need the database (asset resolution, scope, zone) run
in the worker and produce per-item outcomes (partial success, §3.7).

### 3.4 Responses

- `202 Accepted`, `Location: /api/v2/sensor/results/{report_id}`,
  `Retry-After: 2`, body = the status resource.
- An identical replay (same URL, same `Content-Digest`) → `200` with the
  current status. A different digest at the same URL → `409 report-conflict`.
- The response always carries `OpenCTEM-Protocol: 2`.
- The SDK polls the status resource as `Retry-After` advises. Once the v2
  long-poll of [RFC-023 §9.2a](RFC-023-scan-zones-and-scanners.md#92a-heartbeat-doorbell-protocol-v1-additive-extension)
  (`GET /api/v2/sensor/wait`) exists, a report reaching `completed`,
  `failed` or `expired` is one of its wake-up reasons, so polling stops.

### 3.5 Segments

A segmented report exists because a single request is capped (§3.6), not to
resume byte streams.

- **Every segment is a complete, independently valid CTIS document.** It has
  the same `tool` and `metadata` (identical, checked: `409
  segment-header-mismatch`), the findings of that segment, and **every asset
  those findings reference**. An asset may appear in several segments; the
  ingest merge is idempotent. The SDK splitter (`sdk-go/pkg/chunk`) already
  groups findings by asset; it must now copy `tool` and `metadata` into every
  segment.
- Segments may arrive in any order and in parallel (≤ 4 per report in
  flight). Each is processed as it arrives: assets and findings are upserted,
  and the touched asset ids are recorded on the report.
- `commit` declares `segment_count` and `segment_digests`. The server checks
  that it has exactly those segments with exactly those digests (`409
  segment-set-mismatch` otherwise). Only then does it run the report-level
  steps: **auto-resolve** over the union of touched assets, the blinding
  guard (§5.4), the scan/run completion hooks, and notifications.
- An uncommitted report expires 60 minutes after its last segment: state
  `expired`. Its upserts stay, as they would after a crash in v1, but it
  never auto-resolves.
- A single-request `PUT /results/{id}` is exactly one segment plus an
  implicit commit.

Why not tus or the IETF resumable-upload draft: they resume one byte stream
whose bytes mean nothing until reassembled. That requires server-side
reassembly storage, and a per-request signature does not cover the whole
object
([draft §8, §13](https://datatracker.ietf.org/doc/draft-ietf-httpbis-resumable-upload/),
[tus](https://tus.io/protocols/resumable-upload)). Self-describing segments
are each signed, each validated with bounded memory, retried alone, and they
never lose the tool or asset context. That is the v1 chunk bug, fixed by
construction. Resumable byte uploads remain an option for the human import
API (§6) if multi-gigabyte files ever matter.

### 3.6 Limits

| Limit | Value | v1 today |
|---|---|---|
| Request content (encoded) | 16 MiB → `413` | 50 MB body limit |
| Decompressed content | 64 MiB → `413` | 50 MB (middleware), 100 MB (comments) |
| Compression ratio | ≤ 100:1 | 100:1 |
| zstd decoder window / memory | ≤ 8 MiB window, output-capped | memory-capped (api#554) |
| JSON depth | 64 | unbounded |
| Findings / assets per segment | 10,000 / 10,000 | 100,000 / 100,000 per request |
| Segments per report | 256 | 10,000 chunks |
| Findings / assets per report (all segments) | 100,000 / 100,000 | same |
| Property size, properties and tags per asset | unchanged (`MaxPropertySize` 1 MiB, 100, 50) | same |
| Open (uncommitted) reports per sensor | 8 → `429 too-many-open-reports` | — |
| Concurrent ingest requests per tenant | 8 (existing) | 8 |
| Per-item errors returned | first 100, then `errors_truncated: true` | 100 |

All limits are published on `GET /api/v2/sensor/hello` (RFC-023 C3), so the
SDK sizes segments from the server's numbers, not its own constants.

### 3.7 Status resource and partial success

```json
{
  "report_id": "0192a3b4-…",
  "command_id": "…",
  "state": "receiving | queued | processing | completed | failed | expired",
  "segments": { "received": 3, "expected": 3 },
  "accepted":    { "assets": 120, "findings": 812 },
  "rejected":    { "assets": 0,   "findings": 4 },
  "quarantined": { "assets": 0,   "findings": 9 },
  "auto_resolved": 37,
  "errors": [
    { "segment": 1, "pointer": "/findings/17/asset_ref",
      "code": "asset_unresolved", "detail": "finding references no asset in this segment" }
  ],
  "errors_truncated": false,
  "received_at": "…", "updated_at": "…"
}
```

- **Whole-report failure** (steps 4–8) is an HTTP error and nothing is stored.
- **Item failure** (worker: asset unresolved, out of scope, tool not
  permitted for that item) is partial success: `state: completed`,
  `rejected` / `quarantined` counts and `errors[]`, like OTLP's
  `partial_success`. **The client must not resend** a partially accepted
  report; it fixes the producer
  ([OTLP](https://opentelemetry.io/docs/specs/otlp/)).
- `failed` is a server-side processing failure after acceptance (worker
  retries exhausted). The sensor may re-`PUT` the same id, which re-queues.
- `detail` strings are fixed templates. They never quote sensor bytes
  (log-injection and leak lesson; RFC 9457 §5). The `pointer` is built from
  indices and known field names only.

### 3.8 Errors (RFC 9457, `application/problem+json`)

`type` URIs are `https://openctem.io/problems/ingest/<name>`; `title` is
fixed per type. Extension members: `errors[]` (`pointer`, `code`,
`detail`), `limit`, `retryable`.

| Status | `type` name | When | SDK retries? |
|---|---|---|---|
| 400 | `digest-required`, `digest-mismatch`, `invalid-id` | header or path problems | No (a mismatch retries once, then fails: corruption on the path) |
| 401 | `unauthenticated` | bad key or signature | No (re-auth / renew flow) |
| 403 | `scope-denied` | key not scoped for `results`; platform sensor on the unsolicited form | No |
| 404 | `command-not-found` | command not this sensor's, or not open | No |
| 409 | `report-conflict`, `report-committed`, `segment-header-mismatch`, `segment-set-mismatch`, `binding-mismatch` | idempotency and state conflicts | No |
| 411 | `length-required` | no `Content-Length` | No |
| 413 | `content-too-large`, `decompressed-too-large`, `report-too-large` | limits (with `limit`) | No: **split into more segments** |
| 415 | `unsupported-media-type`, `unsupported-encoding` | with `Accept` / `Accept-Encoding` | No |
| 422 | `schema-invalid`, `version-mismatch`, `invalid-json` | strict decode or structural validation (with `errors[]`) | No |
| 429 | `rate-limited`, `queue-full`, `too-many-open-reports` | with `Retry-After` | Yes, honour `Retry-After` |
| 500 | `internal` | server fault, never a payload fault | Yes, backoff |
| 503 | `unavailable` | overload/maintenance, with `Retry-After` | Yes |

Retry policy: retry 429, 500, 502, 503, 504 and network errors with
exponential backoff + jitter, honouring `Retry-After`; never retry other
4xx. This is the rule OTLP and Prometheus RW share. Retries reuse
the same `report_id`, so they are safe.

## 4. Authentication: what ships first and what comes later

**Iteration 1 (ships with v2 results):**

- The sensor key exactly as v1 (`AuthenticateSource`), so v2 results need
  no enrollment change.
- `Content-Digest` is **mandatory** and verified. Honestly, without a
  signature this only detects corruption and buggy proxies. Anyone holding
  the key can compute a digest. It is there so the wire contract and the
  stored fingerprint do not change when signing arrives.
- **Route isolation is not weakened (C-2).** `/api/v2/sensor/*` is a
  separate route group using only the sensor authenticator. User JWTs,
  session cookies and `oct_` API keys are refused there, and sensor keys
  stay refused everywhere outside the sensor groups. Both directions are
  asserted by tests (§7, WP-A5). The `route_authz_coverage_test` allow-list
  gains the group with that reason.

**Iteration 2 (RFC-023 Phase 3, P1/P2):** RFC 9421 with Ed25519, per the
application profile RFC 9421 §1.4 requires us to publish:

- Covered components, all required: `"@method" "@target-uri" "content-type"
  "content-digest"`, plus `"content-encoding"` whenever the header is
  present (the server refuses a request whose `Content-Encoding` is present
  but not covered).
- Parameters: `created` (±5 min skew), `expires` ≤ `created` + 300 s,
  `nonce` (replay cache keyed by `keyid`), `keyid` = sensor key id,
  `alg="ed25519"`, `tag="openctem-sensor-v2"`.
- The digest is verified against the received bytes **and** the signature
  covers the digest (RFC 9421 §7.2.8).
- Per sensor, "signature required" switches on once the sensor has
  registered an Ed25519 key; from then on its bearer key is refused on v2.
  The platform minimum protocol (C7) eventually requires it.

Covering `content-type` costs nothing today (one accepted type), and it is
what keeps the selector honest if a second type is ever added.

## 5. Provenance and malicious-producer controls

### 5.1 Stamped by the server, never read from the body

| Field | Source |
|---|---|
| `tenant_id` | the sensor key; for platform sensors, the command's tenant (command-bound form only) |
| `sensor_id`, `sensor_role`, `trust_tier` | the sensor row |
| `command_id`, `scan_zone_id` | the path, verified; the zone comes from `commands.scan_zone_id` |
| `protocol` | `2` |
| `report_id`, `segment_seq`, `content_digest`, `media_type` | path and headers |
| `received_at` | server clock |

CTIS has no tenant, sensor or zone fields, and the strict decoder rejects
unknown fields, so nothing in the body can claim them.

### 5.2 Claims in the body that are checked

| Claim | Check | On failure |
|---|---|---|
| `tool.name` | must be in the sensor's declared tools; when command-bound, must equal the command's tool. Unlike v1 there is **no** allow-all for sensors with no declared tools. | `422 tool-not-permitted` (whole report) |
| `metadata.id` | empty or equal to `report_id` | `422` |
| assets on a zone-bound command | addresses must lie in the command's targets or zone | item **quarantined**, not merged (counted, reviewable) |
| finding → asset | must reference an asset in the same document, or the command's target asset | item **rejected** `asset_unresolved` (v1's fallback assets in `processor_assets.go` are never created on v2) |

### 5.3 Shared catalogs

v2 sensor reports never write the global vulnerability catalog
(`CVEProcessor` "fill-blanks" today). Sensor-supplied CVE text, CVSS and
references are stored on the tenant's finding as *reported* attributes. The
global catalog is written only by trusted feeds (NVD, KEV, EPSS). This
closes "a malicious sensor poisons shared catalogs" for v2; v1 gets the same
gate as a separate fix (§10).

### 5.4 Auto-resolve and blinding

Auto-resolve runs only on **commit**, only for `coverage_type: full` on a
default branch (unchanged rule), only for a permitted tool, and only over
assets this report touched. A commit that would resolve more than 50% (and
more than 100) of the open findings for that tool on those assets is
**held for review** (RFC-023 C-4 "blinding"). It is shown on the status
resource as `auto_resolve: held`.

### 5.5 Untrusted strings

Everything a sensor sends is untrusted (C-6). Log fields go through the
existing `sanitizeLogField` (`strings.ReplaceAll` of `\n`/`\r`, the form
CodeQL recognises). Problem `detail` and status `errors[].detail` are fixed
templates. Metrics labels come from closed enums only (problem type,
encoding, outcome), never from tool names or ids.

## 6. The human / CI import API

| | Sensor results (v2) | Import |
|---|---|---|
| Who | sensors (machine identity) | users (session/JWT) and `oct_` API keys |
| Path | `/api/v2/sensor/results/…` | `POST /api/v1/imports`, `GET /api/v1/imports/{id}` |
| Permission | sensor key scope `results` | new `findings:import` (Go + seed migration + UI constants) |
| Formats | CTIS only | allow-list by `Content-Type`: `application/vnd.openctem.ctis.v1+json`, `application/sarif+json` (IANA-registered), later `application/vnd.cyclonedx+json` (IANA-registered) and `application/vnd.openctem.import.nessus+xml` |
| Context | command / sensor | query parameters: `asset_id`, or `repository` + `ref` + `commit`, and `category` (separates analyses so auto-resolve stays within one); required when the format carries no asset (SARIF without `versionControlProvenance` → `422`) |
| Conversion | none on the server | on the server, in a bounded converter: own size, time and memory budget, panic recovery, no network, XML with no DTD (Go's `encoding/xml` has no external entities, but depth and size are still capped). Iteration 2 moves it to a separate process (`server convert` subcommand under rlimits/seccomp) or WASM (open question) |
| After conversion | — | **the same** strict decoder, validation, provenance (`source=import`, `actor=user`), queue and status shape |
| Rate limit, audit | sensor buckets | user/tenant bucket (10/min, like the existing import routes); audit event `finding.imported` with actor, format, digest, counts |

No auto-detection anywhere: v1's `AutoDetect` sniffing is not carried over.
`application/json` is `415`, because "JSON" is not a format. Each format
added to the allow-list needs an owner, a fuzz corpus and a golden test,
which is why the list stays short.

CI guidance: the recommended path stays the `openctemio/sensor:ci` image (an
ephemeral sensor; converts client-side, gets the v2 contract). The import
API is for "I already have a SARIF file" with `curl`.

## 7. Implementation plan

Work packages are ordered and independently mergeable. Every API package is
behind `SENSOR_PROTOCOL_V2_RESULTS=false` until WP-A7 flips the default, so
nothing is advertised half-built.

### 7.1 api

**WP-A1 — `pkg/sensorproto/v2` (wire vocabulary).** New package, sibling of
`legacyv1`: media type and encoding constants plus `ParseResultsContentType`
(exact match), header names, problem type URIs and titles, status/limits
DTOs, `hello` DTO.
*Tests:* unit tests for media-type parsing (case, parameters, `application/json`,
`charset`), golden JSON for every problem type and the status resource
(`internal/infra/http/handler/testdata/protocol_v2/*.golden`).
*Accept:* no other package defines a v2 wire string; the `sensorvocab` lint
stays green.

**WP-A2 — edge middleware.** `internal/infra/http/middleware/`:
`RequireContentType`, `RequireContentLength` (411/413), `ContentDigest`
(RFC 9530 parse, hashing reader, verify; reusable for signing later), and a
v2 configuration of the existing bounded decompressor (`decompress.go`: add
a zstd window cap, return typed errors that map to problems). Chain order as
§3.3, reusing `ingestMiddlewareChain` for rate limit and concurrency.
*Tests:* table tests per gate; a gzip and a zstd bomb (ratio and absolute)
→ `413` with RSS bounded; digest over compressed vs decompressed bytes;
oversized `Content-Length` refused before read.
*Accept:* no handler sees an unverified or unbounded body.

**WP-A3 — strict CTIS decode.** `internal/app/ingest/strictjson.go`: a
token-level pre-pass (duplicate keys, depth, invalid UTF-8, trailing data)
followed by `DisallowUnknownFields` decode, both reused by v2 and imports;
`ValidateReportV2` extending `validator.go` (tool required, `metadata.id`
rule, per-segment limits).
*Tests:* parser-differential cases (duplicate key, `\ud800`, `1E400`, trailing
garbage), depth 65, unknown field; a Go fuzz target `FuzzStrictCTIS`
seeded from `schemas/ctis/v1` examples.
*Accept:* fuzzing 10 min in CI nightly without a panic; a new
`ctis_schema_parity_test.go` decodes every `schemas/ctis/v1` example with
the strict decoder and fails if the Go structs and the JSON Schema disagree
on a field name, a required field or an enum value (the api has no such
check today; sdk-go's `ctis-parity` job compares sdk-go with ctis only).

**WP-A4 — migration (expand only).** New `ingest_reports` table: `id`,
`tenant_id`, `sensor_id`, `report_id`, `command_id`, `scan_zone_id`, `state`,
`segment_count`, `touched_asset_ids uuid[]`, header digest, counts, errors
`jsonb`, `expires_at`, timestamps; unique `(tenant_id, sensor_id,
report_id)`; composite FK same-tenant rule as RFC-023 Phase 1. `ingest_jobs`
gains nullable `protocol`, `ingest_report_id`, `segment_seq`,
`content_digest`, `media_type`; the idempotency index for v2 rows is
`(ingest_report_id, segment_seq)`.
*Tests:* up/down round-trip (existing schema-drift and migration-safety
jobs); repository DB tests on a migrated database
(`internal/infra/postgres/ingest_report_repository_db_test.go`).
*Accept:* no destructive statement; v1 rows unaffected.

**WP-A5 — routes and handlers.** `internal/infra/http/routes/sensor_v2.go`
mounts `/api/v2/sensor` with `AuthenticateSource` only;
`internal/infra/http/handler/sensor_results_v2_handler.go` implements PUT
whole/segment, commit, GET, DELETE and `hello`, calling the ingest service
through a new `ingest.SubmitV2(ctx, Provenance, segment)`, which stores the
segment and enqueues on `ingest_jobs` (the RFC-005 queue; the worker runs
whenever v2 is enabled, independent of `INGEST_MODE`).
*Tests:* handler tests per status code in §3.8; golden wire files; a route
isolation test: sensor key on a user route → 401, user JWT / `oct_` key /
cookie on `/api/v2/sensor/*` → 401; `tests/unit/route_authz_coverage_test.go` updated.
*Accept:* every row of §3.8 is reachable in a test.

**WP-A6 — ingest semantics for v2.** In `internal/app/ingest`: a
`Provenance` struct carried through `Input`. Options: `RequireAssetForFindings`
(no fallback asset), `StrictToolGate` (no empty-tools allow-all),
`CatalogWrites=false` (§5.3), command-binding and zone quarantine hooks,
`DeferAutoResolve` (record touched assets on `ingest_reports`), and a
`CommitReport` that runs auto-resolve, the blinding guard and completion
hooks once.
*Tests:* unit tests per rule; an integration test on a migrated DB
(`tests/integration/ingest_v2_test.go`): a 3-segment report out of order,
auto-resolve only after commit, an expired uncommitted report never
resolves, an asset-less finding rejected with no fallback asset created,
tool spoofing refused, CVE text not written to the global catalog, two
tenants with the same `report_id` isolated.
*Accept:* v1 behaviour unchanged (the existing ingest tests are untouched
and green).

**WP-A7 — advertise and observe.** `GET /api/v2/sensor/hello` (protocol,
features `results`, limits) and `X-OpenCTEM-Protocol` advertising `2` when
enabled (C3). Metrics `ingest_v2_requests_total{outcome,problem}`,
`ingest_v2_bytes{stage=encoded|decoded}`, `ingest_v2_items_total{result}`;
v1 per-route counters `ingest_v1_requests_total{route}` (for §8.3). Flip
the default to enabled.
Discovery for v1 sensors reuses the doorbell's opt-in (api#619,
§9.2a): a sensor that sends `X-OpenCTEM-Sensor-Features: results-v2` on its
v1 heartbeat gets `X-OpenCTEM-Protocol: 2` back, and v1 response bytes do
not change for anyone else (`flow.golden`).
*Accept:* the Sensors page data (fleet by protocol) can show who still uses
which v1 route.

**WP-A8 — import API** (after the sensor path ships). `POST/GET
/api/v1/imports`, `findings:import` permission (three-place rule), the
converter wrapper over `internal/infra/adapters/sarif` and the ctis-lib
SARIF converter, context parameters, audit event, rate limit; UI upload
later.
*Tests:* a SARIF without provenance and without `repository` → `422`; XML
billion-laughs and depth → refused; conversion timeout; permission matrix.

### 7.2 sdk-go

**WP-S1 — v2 results client.** `pkg/client`: `PushResultsV2(ctx, report,
opts)` with UUIDv7 `report_id`, zstd, `Content-Digest`, problem+json
decoding, the §3.8 retry table, and segmentation from the server's `hello`
limits. It reuses `pkg/chunk` (splitter + SQLite storage for crash-safe
resume of uncommitted reports), changing the splitter so every segment
carries `tool` and `metadata`. Protocol selection: `hello` says v2 →
v2; otherwise v1 exactly as today (C3).
*Tests:* unit tests against `httptest` for each status; the splitter
invariant (every finding's `asset_ref` resolves inside its own segment).

**WP-S2 — converters own the context.** `pkg/adapters` (SARIF, nuclei,
trivy, semgrep, gitleaks, vuls) must emit an asset for every finding: SARIF
takes repository/commit from the command payload or `pkg/gitenv`, and fails
client-side when neither exists (the v1 shared-fake-asset bug never reaches
the server).
*Tests:* golden CTIS per adapter fixture; the asset-required invariant.

**WP-S3 — conformance suite.** The conformance suite RFC-023 D23 plans
(`platform/conformance`, not built yet) starts with these ingest cases: a
fake control plane asserts headers and digest, refuses each §3.8 class, and
checks the SDK retries only what it should, splits on `413`, never resends a
partially accepted report, and reuses `report_id` on retry.
*Accept:* required for the *verified* trust tier (D22/D23).

### 7.3 sensor (`agent` repo)

**WP-G1.** Bump to the SDK with WP-S1/S2; add `SENSOR_PROTOCOL=auto|v1|v2`
(default `auto`); keep the retry queue.
*Tests:* end-to-end with docker compose: the sensor runs a semgrep scan
against a fixture repository, pushes over v2, and the test checks the
findings in the DB, the status `completed`, and that a re-push of the same
report is a replay.

### 7.4 Keeping both protocols honest in CI

- **`Protocol v1 Compatibility`** (`compat-v1` job, `scripts/compat-v1.sh`,
  pinned to the last released SDK) stays unchanged and required. Any v2 work
  that alters a v1 byte fails it. The golden v1 tests
  (`protocol_v1_golden_db_test.go`) stay as they are.
- **New `Protocol v2 Conformance` job**, same services and setup:
  `scripts/compat-v2.sh` runs `tests/compat/v2` (its own module, pinned to
  sdk-go **HEAD of the v2 branch until the first v2 release, then the last
  released**) through a single PUT, a 3-segment report, an identical replay
  (`200`), a conflicting replay (`409`), a gzip bomb (`413`),
  `application/json` (`415`), a missing digest (`400`), a duplicate-key body
  (`422`), and a user token on a v2 route (`401`). It then checks DB rows
  and provenance.
- Golden v2 wire files are reviewed like code: changing one is a protocol
  change.

### 7.5 Out of scope for iteration 1

RFC 9421 signing (iteration 2, RFC-023 Phase 3); zone quarantine for
unsolicited reports from multi-zone sensors (needs D15 networks); the
blinding guard's review UI (the hold and the flag ship; the queue UI
later); the import API (WP-A8 follows); a separate-process or WASM sandbox
for import converters; v2 runtime telemetry and validation evidence; the
`/check` and `/baseline-diff` queries on v2; protobuf encoding; multi-kind
envelopes; resumable byte uploads; retiring any v1 route.

### 7.6 What iteration 1 shipped (api)

| WP | Where | Notes |
|---|---|---|
| A1 | `pkg/sensorproto/v2` | Paths, media type, codings, Content-Digest parser, the closed problem table, status, limits, hello; golden files. |
| A2 | `internal/infra/http/middleware/ingest_v2.go` | The §3.3 edge chain; its own bounded gzip/zstd decoder (the v1 `decompress.go` is untouched). `V2Observe` records the request metrics for every answer, including edge refusals. |
| A3 | `internal/app/ingest/strictjson.go` | I-JSON pre-pass + one `DisallowUnknownFields` decode; `FuzzStrictCTIS` nightly (`.github/workflows/fuzz.yml`); `TestCTISSchemaParity` found 32 differences between the ctis v1.1.0 structs and `schemas/v1`, recorded as reviewed exceptions (the schema-only ones are refused by the strict decoder until ctis is fixed). |
| A4 | migration 000237, `pkg/domain/ingestreport`, `postgres/ingest_report_repository.go` | Per-segment outcomes stored under their number (a retried segment is not counted twice); `ClaimFinalize` runs the commit steps exactly once. |
| A5 | `routes/sensor_v2.go`, `handler/sensor_results_v2_handler.go`, `ingest/v2_receiver.go`, migration 000239, `api/openapi/sensor-protocol-v2.yaml` | Every client-visible row of §3.8 is reached in `routes/sensor_v2_routes_db_test.go`; 503 `unavailable` has no producer yet. |
| A6 | `ingest/v2.go`, `ingest/v2_jobs.go` | `Options` on the existing pipeline (all off for v1), item outcomes, `CommitV2Report` with the blinding guard, `tests/integration/ingest_v2_test.go`. |
| A7 | `handler/ingest_handler.go` (heartbeat), `internal/metrics` | Discovery header, metrics, default on. |

Not built: the fleet-by-protocol view of the Sensors page (the per-route v1
counter is a Prometheus metric without a tenant label; per-tenant usage can
be read from `ingest_reports` for v2), zone quarantine (§5.2, counted as 0),
the command-target fallback asset (§10.1), D21 key scopes, signing.

## 8. Migration and compatibility

### 8.1 v1

Frozen (RFC-023 C1). Served by `pkg/sensorproto/legacyv1`, unchanged,
proven by `compat-v1`. v2 shares the ingest core but not the wire.

### 8.2 SDK and third parties

- SDK users upgrade and get v2 automatically when the server advertises it.
  Old SDKs keep v1.
- Non-Go third parties implement one documented request: CTIS JSON plus four
  headers. They validate locally against `schemas/ctis/v1` (published JSON
  Schema) and prove it with the conformance suite. A reference converter
  CLI (`openctem-convert sarif|nuclei|trivy → CTIS`, built from
  `pkg/adapters`) is published with the SDK so shell-only producers need no
  Go.
- People holding a raw file use the import API.

### 8.3 Server-side adapters and retiring v1 ingest

1. **Measure:** WP-A7's per-route v1 counters, per tenant, on the Sensors
   page.
2. **Shrink:** `internal/infra/adapters` exists only for v1 `/ingest/scan`,
   `/ingest/sarif` and `/ingest/recon` and for imports. The SDK client
   itself uses only `/ingest`, `/ingest/check`, `/ingest/baseline-diff` and
   `/ingest/chunk`; the per-format routes are reached only by `curl` users
   following the docs. Once the import API exists, the docs move to it.
3. **Lever:** a new **minimum ingest protocol** (platform-wide, overridable
   per tenant, default 1), separate from C7's job lever, because RFC-023 D24
   keeps collectors below the minimum pushing. Raising it to 2 makes v1
   ingest routes answer `410` with a problem body naming the v2 resource.
   Before that, the v1 ingest responses carry `Deprecation` / `Sunset`
   headers (RFC 9745 / RFC 8594): additive, allowed by C1. Retire in two
   steps: first the server-side-conversion routes (`/ingest/scan`,
   `/ingest/sarif`, `/ingest/recon`), then the CTIS routes (`/ingest`,
   `/ingest/ctis`, `/ingest/chunk`).
4. **Delete:** after step 3 reaches every tenant, delete the adapters that
   are not on the import allow-list (today: all but SARIF). This also
   removes the RFC-002 duplication between `internal/infra/adapters` and
   `sdk-go/pkg/adapters`.

## 9. Risks

| Risk | Mitigation |
|---|---|
| Third parties without the Go SDK find CTIS-only harder than "post your SARIF" | the import API, the converter CLI, the JSON Schema and the conformance suite |
| A strict decoder refuses data v1 accepted (duplicate keys, invalid UTF-8) | only on v2; the SDK produces conforming JSON; the `compat-v2` job checks the SDK against the server |
| Deferred auto-resolve leaves stale findings open when sensors never commit | the SDK commits in a `defer`; uncommitted reports expire visibly (`expired` on the status and in metrics per sensor) |
| Removing fallback assets drops findings v1 kept | they are counted as `rejected` with a reason, never silently; the adapters are fixed in WP-S2 |
| `ingest_jobs` grows with per-segment rows | 10k-finding segments, the existing retention, and `report-level` pruning on completion |
| The digest without a signature is mistaken for authentication | stated in §4 and in the operator docs; signing is iteration 2 |

## 10. Open questions for the product owner

1. **Raw-file import timing.** Ship the import API (WP-A8) in the same
   release as v2 results, or after? It decides when the v1 per-format
   routes can start retiring.
2. **Converter isolation.** For the import API's iteration 2: a separate
   process with rlimits/seccomp, or WASM (wazero)? The process is simpler
   and fits the existing binary; WASM is stronger and portable.
3. **Catalog gate for v1.** Apply §5.3 (no sensor writes to the global
   vulnerability catalog) to v1 as well? It changes v1 behaviour, not its
   wire, so it is allowed by C1 but visible in data.
4. **Blinding threshold.** Is 50% / 100 findings the right default, and is
   it per tenant?
5. **Minimum ingest protocol.** Agree to a separate lever from C7 (§8.3),
   with a deprecation window: proposal 6 months after v2 ships.

### 10.1 Decisions taken (2026-10-01)

The product owner asked for the best option to be researched and
implemented. Each question takes the answer this RFC already recommends;
where it recommends none, the safest default is chosen.

| # | Decision | Basis |
|---|---|---|
| 1 | **The import API (WP-A8) ships after v2 results**, not in iteration 1. The v1 per-format routes therefore do not start retiring with this release. | §7.1 WP-A8 ("after the sensor path ships") and §7.5. |
| 2 | **WASM (wazero) is the target sandbox** for the import converters' iteration 2. Until then no server-side conversion runs on v2 at all, because the import API is not built. | No recommendation in the RFC; WASM is the stronger isolation (no syscalls, no network, no file system by construction) and is portable. Revisit if a converter cannot be built for `wasip1`. |
| 3 | **Yes, v1 gets the catalog gate (§5.3)**, as its own follow-up PR after v2 results, so the visible data change is reviewed alone. v2 never writes the global catalog from the first commit. | §5.3 ("v1 gets the same gate as a separate fix"). |
| 4 | **50 % and more than 100 findings** is the blinding threshold, platform-wide, configurable with `SENSOR_V2_BLINDING_RATIO` and `SENSOR_V2_BLINDING_MIN_FINDINGS`. Not per tenant yet: a per-tenant override needs a settings surface that does not exist, and a tenant admin lowering their own guard is not the safe default. | §5.4. |
| 5 | **A separate minimum-ingest-protocol lever**, default 1, with `Deprecation` / `Sunset` on v1 ingest 6 months after v2 ships. Not built in iteration 1 (§7.5 keeps every v1 route). | §8.3, proposal in §10 Q5. |

Clarifications made while implementing (the RFC was silent or
inconsistent):

- **Two protocol headers.** v2 responses carry `OpenCTEM-Protocol: 2`
  (§3.4). A v1 response advertises v2 with `X-OpenCTEM-Protocol: 2`
  (RFC-023 C3), and only to a sensor that sent
  `X-OpenCTEM-Sensor-Features: results-v2`, so no deployed sensor sees a new
  header.
- **Extra problem types.** `invalid-encoding` (400: the body does not decode
  with the declared `Content-Encoding`), `invalid-request` (400: a malformed
  commit body), `report-not-found` (404: status of an unknown report) and
  `report-expired` (409: a segment or commit for an expired report). All are
  in the closed table of `pkg/sensorproto/v2`.
- **Key scopes (D21) do not exist yet.** Every sensor key implicitly holds
  `results`. Sensor role and trust tier are not modelled either; the
  provenance stamps the legacy sensor `type` until RFC-023 adds them.
- **Platform sensors are refused on v2** (`403 scope-denied`, both forms).
  `sensors.tenant_id` is NOT NULL in this schema and the platform-job tables
  are not part of the open-source API, so there is no tenant-less sensor to
  bind to a command's tenant. `ingest_reports` therefore keys the sensor with
  the composite `(tenant_id, sensor_id)`, the same-tenant rule of RFC-023
  Phase 1.
- **Per-report totals are reserved at accept** (migration 000239), so the
  100,000 assets / findings per report limit of §3.6 holds across parallel
  segments.
- **Commit digests are sha-256.** The server stores the sha-256 of every
  segment's received bytes whatever algorithm the sensor declared, and a
  commit lists those canonical sha-256 members.
- **No command-target fallback asset.** §5.2 allows a finding to fall back to
  the command's target asset. A command's targets are free-form payload today,
  not asset ids, so iteration 1 accepts only assets in the same document. A
  finding without `asset_ref` is bound to the segment's single asset when it
  has exactly one, and rejected otherwise.
- **Zone quarantine** applies to command-bound reports only and is deferred
  with §7.5's "zone quarantine for unsolicited reports"; iteration 1 counts
  `quarantined` as 0.

## 11. Appendix: survey of ingest APIs

"One / many" is the endpoint shape; "Format by" is how the payload format
is chosen. "—" means not documented. Links are in §12.

### 11.1 Telemetry ingest

| System | One / many | Format by | Sync / async | Size | Idempotency | Errors and partial success | Auth |
|---|---|---|---|---|---|---|---|
| OTLP/HTTP | one per signal (`/v1/traces`, `/v1/metrics`, `/v1/logs`) | `Content-Type` (`application/x-protobuf` / `application/json`), gzip | sync `200` | recommended 64 MiB (`413`) | none (duplicates accepted) | `200` + `partial_success` (rejected counts), client must not retry; `400` final; `429/502/503/504` retry with `Retry-After` | transport |
| Splunk HEC | path picks the envelope (`/collector/event` JSON vs `/collector/raw`) | path; `sourcetype` picks parsing | `200` = "appears valid"; optional indexer ack (channel + `ackId` poll) | — | none | numeric codes; no per-event partial success | `Authorization: Splunk <token>` |
| Loki | one (`/loki/api/v1/push`) | `Content-Type` (protobuf+snappy / JSON) | `204` | — | — | `400` | tenant header |
| Prometheus RW 2.0 | one | `Content-Type: application/x-protobuf;proto=…`; `415` otherwise | `204` (`202` if async) | — | receivers must be idempotent | written-count headers even on `400` | transport |

### 11.2 What the survey settles

- **Shape:** one endpoint per *data kind* dominates (OTLP, Loki).
  Generic endpoints (HEC) label every item inside the body, because they mix
  kinds.
- **Format selection:** by `Content-Type` for wire formats (OTLP, Loki, PRW,
  CloudEvents binary mode). Body fields choose *semantic* types (HEC
  `sourcetype`), not parsers. A body field that selects a parser carries the
  largest parser surface.
- **Canonical format:** a platform that owns its data model accepts exactly
  one format on push and leaves conversion to the client.
- **Async:** `202` + a status to poll is the norm for security results.
- **Partial success:** schema failure rejects the report; item failure is
  reported inside a success (OTLP), and the client does not resend.

## 12. Sources

**Telemetry / observability ingest**
- OpenTelemetry OTLP: https://opentelemetry.io/docs/specs/otlp/
- Splunk HEC formats: https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.4/get-data-with-http-event-collector/format-events-for-http-event-collector
- Splunk HEC indexer acknowledgement: https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/about-http-event-collector-indexer-acknowledgment
- Grafana Loki push API: https://grafana.com/docs/loki/latest/reference/loki-http-api/
- Prometheus Remote Write 1.0: https://prometheus.io/docs/specs/prw/remote_write_spec/
- Prometheus Remote Write 2.0: https://prometheus.io/docs/specs/prw/remote_write_spec_2_0/

**Standards**
- RFC 9110 HTTP Semantics: https://www.rfc-editor.org/rfc/rfc9110.html
- RFC 6838 Media Type Specifications: https://www.rfc-editor.org/rfc/rfc6838.html
- IANA media types (`application/sarif+json`, `application/vnd.cyclonedx+json`, `application/spdx+json`): https://www.iana.org/assignments/media-types/media-types.xhtml
- RFC 9457 Problem Details: https://www.rfc-editor.org/rfc/rfc9457.html
- RFC 9530 Digest Fields: https://www.rfc-editor.org/rfc/rfc9530.html
- RFC 9421 HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421.html
- Idempotency-Key draft (expired 2026-04-18): https://www.ietf.org/archive/id/draft-ietf-httpapi-idempotency-key-header-07.html
- Asynchronous Request-Reply pattern: https://learn.microsoft.com/en-us/azure/architecture/patterns/asynchronous-request-reply
- Resumable uploads draft: https://datatracker.ietf.org/doc/draft-ietf-httpbis-resumable-upload/
- tus 1.0: https://tus.io/protocols/resumable-upload
- CloudEvents spec: https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md
- CloudEvents HTTP binding: https://github.com/cloudevents/spec/blob/main/cloudevents/bindings/http-protocol-binding.md
- OCSF: https://schema.ocsf.io/
- RFC 9562 UUIDs: https://www.rfc-editor.org/rfc/rfc9562.html
- RFC 9745 Deprecation header: https://www.rfc-editor.org/rfc/rfc9745.html
- RFC 8594 Sunset header: https://www.rfc-editor.org/rfc/rfc8594.html

**Security engineering**
- LangSec: https://langsec.org/
- Momot et al., "The Seven Turrets of Babel" (IEEE SecDev 2016): https://www.semanticscholar.org/paper/ae4e54c65d5139c21b2a9499d1f24c7e3e14af05
- RFC 8259 §4 (duplicate names): https://www.rfc-editor.org/rfc/rfc8259.html#section-4
- RFC 7493 I-JSON: https://www.rfc-editor.org/rfc/rfc7493.html
- OWASP XXE prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- OWASP file upload: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP input validation: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- CWE-409: https://cwe.mitre.org/data/definitions/409.html
- Fifield, "A better zip bomb" (WOOT 2019): https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf
