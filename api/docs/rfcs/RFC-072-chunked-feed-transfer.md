# RFC-073: Chunked feed transfer

| | |
|---|---|
| Status | Accepted (2026-10-10, delegated; D1–D8 adopted as recommended, §12). F3/F4 implemented in #1701, F1/F2 in programfeed#5 and vulnfeed#2; F5 pending |
| Scope | sdk-go (`pkg/transfer`, `pkg/transfer/bundle`), openctemio/programfeed and openctemio/vulnfeed (bundle writers), api (feed importers, migration `feed_checkpoints`) |
| Architecture | [feed-transfer.md](../architecture/feed-transfer.md); sdk-go `docs/ARCHITECTURE.md` "Feed transfer" |
| Related | RFC-005 (asynchronous ingest), RFC-026 (sensor results ingest, protocol v2 segments), RFC-061 (content packs), RFC-065 §16 (public program feed), RFC-066 §5.5 (vulnerability feed) |

## 1. Summary

Feeds will carry large data: the vulnerability feed already allows record
files of 512 MiB (2 GiB decompressed), and the program feed grows with every
platform it reads. Today each bundle is a handful of whole files that the
platform downloads in one request, verifies in full and applies in one
transaction. A dropped connection restarts the download from zero, a crash
mid-apply restarts the import from zero, and memory grows with the feed.

This RFC defines one transfer layer, in sdk-go, used by every feed and every
collector:

- **Pull** (feed to platform or sensor): bundle format v2 — a signed pointer
  pinning signed manifests that list content-addressed chunks (gzip JSON
  Lines, a few MiB each). A consumer verifies every signature, pin and cap
  before the first chunk, then fetches and applies chunk by chunk, each in
  its own transaction, with a durable checkpoint. The fetcher retries with
  back-off, honors Retry-After, resumes with Range requests, and falls back
  through mirrors to a local directory, all through the SSRF-guarded client.
- **Push** (sensor or collector to platform): the existing results protocol
  v2 (segments, `report_id` idempotency, resumable progress) and the
  encrypted, capped outbox already are the chunker and the store-and-forward
  spool. This RFC adopts them as the push half and lists what remains.

## 2. Current state

- **Producers** (`openctemio/programfeed`, `openctemio/vulnfeed`,
  `internal/bundle`): one gzip JSONL file per record type
  (`snapshot-programs.jsonl.gz`, `snapshot-vulns.jsonl.gz`, …) plus a DSSE
  manifest listing each file's sha256, size and record count, a signed
  `latest` pointer and an offline-root key set. Caps: program feed 128 MiB
  per file, vulnerability feed 512 MiB per file and 2 GiB decompressed. A
  local program feed build today is ~3.2k programs, 3.3 MB raw, 160 KB
  compressed; the vulnerability feed is the large one.
- **Consumers** (api): `internal/app/vulnfeed` (#1671) downloads each file
  with one GET (`httpsec.SafeHTTPClient`, 10 min timeout, no retry, no
  resume), verifies the directory (`pkg/vulnbundle`) and applies.
  `internal/app/programfeed` (#1687) reads a `BundleSource` directory,
  verifies (`pkg/programfeed`, `pkg/feedsign`) and applies all programs in
  one repository call. The applied sequence is stored per feed
  (`threatintel` sync status; program feed state).
- **Push**: sensors send CTIS reports as protocol v2 segments
  (`chunk.SplitSegments`, `client.PushResultsV2`, RFC-026) with a stable
  `report_id`, a `Content-Digest` per segment and resumable `V2Progress`.
  Every report is written to the outbox before the first send
  (`pkg/outbox`: AES-256-GCM sealed files, 0600, byte and age caps with
  oldest-first eviction, circuit breaker, Retry-After, metrics). The
  platform accepts segments idempotently (same `report_id` and digest: 200,
  nothing stored twice) and ingests asynchronously (RFC-005).

The gaps are all on the pull side: no chunking, no resume, no retry, no
mirror, no checkpoint, unbounded memory in the program feed importer, and
the format and verifier are copied in four places (two producers, two
consumers).

## 3. Goals and non-goals

Goals:

1. One format and one consumer for every feed; each feed keeps only its
   record schema, its validation and its apply.
2. Bounded memory and bounded work per step, whatever the feed size.
3. A crash, a restart or a dropped connection resumes; it never restarts a
   multi-GB import, never applies a chunk of an older sequence, and never
   marks a partial bundle applied.
4. Every byte is covered by one signature; mirrors and caches cannot change
   content.
5. Unchanged data is not downloaded again.

Non-goals: peer-to-peer distribution; a new signing scheme (the DSSE
envelope, offline root and key set stay as they are); per-tenant feeds
(feed data is platform-wide; §9.6).

## 4. Bundle format v2

A release is a flat set of files (flat, so it fits release-asset hosting,
object stores and a USB stick alike):

| File | Content |
|---|---|
| `keyset.dsse.json` | unchanged: online keys signed by the offline root |
| `latest.v2.dsse.json` | signed **pointer** |
| `snapshot.v2.manifest.dsse.json` | signed **manifest** of the full record set |
| `delta.v2.manifest.dsse.json` | signed manifest of the changes since `base_sequence` (optional) |
| `sha256-<hex>.jsonl.gz` | **chunks**, named by the sha256 of their bytes |

**Pointer** (`openctem.bundle.pointer/v2`, payload type
`application/vnd.openctem.<feed>.pointer.v2+json`): `feed`, `sequence`,
`snapshot` and optional `delta` as `{name, sha256, size}` of the manifest
envelope, `base_sequence`, `created_at`, `expires_at`.

**Manifest** (`openctem.bundle/v2`, payload type
`application/vnd.openctem.<feed>.manifest.v2+json`): `feed`, `sequence`,
`kind` (`snapshot`|`delta`), `base_sequence`, `created_at`, `expires_at`,
`streams` (ordered; each `{name, records, chunks[]}`), and `meta` (the
feed's own signed metadata: sources, licenses, attribution, stats, collector
build; opaque to the SDK). Each chunk is `{sha256, size, uncompressed,
records, first_id, last_id}`.

**Chunks**: gzip (no name, no mtime: equal records give equal bytes) of
JSON Lines, one record per line, records in strictly ascending id order per
stream. Streams are applied in manifest order (for example `products`,
`vulns`, `ranges`), chunks in order.

**Chunk boundaries** are content-defined: a chunk ends after a record whose
FNV-1a(id) is 0 modulo the target (default 2 000 records per chunk), with a
minimum of a quarter of the target, and hard caps of 4× the target records
and 48 MiB uncompressed. One changed record therefore changes one chunk; an
insertion or deletion changes one or two. Typical feed records give 1–8 MiB
compressed per chunk.

**Delta** chunks use the same writer on the changed records only (complete
new records, plus the feed's change-log stream).

**Dedupe across releases**: unchanged chunks keep their name. Consumers keep
the applied bundle's chunks in a content-addressed cache and fetch only new
names; an object-store mirror stores each chunk once. On release-asset
hosting each release still uploads its chunks (each release is
self-contained), so storage there is not deduplicated, but consumer
bandwidth is.

## 5. Consumer

`bundle.Consumer.Run` (sdk-go) runs one feed, one run at a time (the caller
holds the lock the importers already take):

1. Load the checkpoint: `applied` (last complete sequence), and the bundle in
   progress (`in_progress`, `kind`, `manifest` digest, `next_chunk`).
2. Fetch the key set and build the verifier through the caller's `Trust`
   (pinned root, key-set version never lower than accepted before — the
   existing `feedsign` rules). Fetch and verify the pointer: signature,
   schema, feed, expiry, validity at most 8 days, no future `created_at`.
3. `sequence < applied`: refuse (`ErrRollback`: stale mirror or replay).
   `sequence == applied`: up to date, nothing fetched.
4. Pick the manifest: the bundle in progress if it is this sequence (same
   kind, same manifest digest); else the delta only when
   `base_sequence == applied`; else the snapshot.
5. Fetch the manifest; check its size and sha256 against the pointer's pin,
   its signature, schema, feed, sequence, kind, base and expiry; check the
   caps (chunk count, per-chunk compressed and uncompressed size and
   records, total bytes, stream record sums) — all before any chunk.
6. Save the checkpoint "in progress" (unless resuming).
7. For each chunk from `next_chunk`: fetch it (hash and size verified before
   it lands in the cache), hand it to the feed's `Applier.ApplyChunk`, which
   streams the records (`Chunk.Records`: refuses more decompressed bytes or a
   different record count than declared, and a line over the cap — before
   the offending line reaches the applier), validates each record with the
   feed's domain parser and upserts them in **one transaction**, then save
   the checkpoint with `next_chunk + 1`.
8. `Applier.Complete` (a snapshot removes records it no longer holds: rows
   whose `feed_sequence` is older), then save `applied = sequence`, clear the
   bundle in progress, and prune cached chunks not in this manifest.

Rules for appliers:

- **Idempotent, sequence-guarded upserts**: keyed by record id, and
  `ON CONFLICT … DO UPDATE … WHERE stored.feed_sequence <= excluded.feed_sequence`.
  A crash between the chunk's commit and the checkpoint save replays the
  chunk; the guard makes the replay a no-op and keeps a newer record.
- **Exactly-once** where it matters: the platform's applier writes the
  checkpoint row in the chunk's transaction (the consumer then saves it
  again, idempotently).
- A failed chunk rolls back and leaves the checkpoint at that chunk; the
  next run (scheduled tick) resumes there.
- A bundle abandoned half-way because a newer sequence appeared is never
  continued as a delta base: the newer delta's base is then not `applied`,
  so the consumer takes the snapshot, whose `Complete` sweep restores
  consistency.

Memory is one chunk's decoder plus the applier's batch; the manifest is at
most 8 MiB.

## 6. Network

`transfer.Fetcher` (sdk-go):

| Concern | Behavior |
|---|---|
| Origins | ordered: primary release URL → configured mirrors → local directory (air-gapped upload). `https` (http only for tests), no credentials, query or fragment in the URL |
| Client | caller's; default `httpsec.SafeHTTPClient` (SSRF guard on every dial, safe redirects, content proxy). The api passes its own `pkg/httpsec` client |
| Retries | per origin, default 4 attempts, exponential back-off 1 s → 60 s with jitter in [d/2, d] |
| Transient | network error, stall, 408, 425, 429, 5xx |
| Retry-After | seconds or HTTP date, honored up to 5 min; longer → next origin |
| Permanent | 404 and other 4xx, a hash or size mismatch on a full download → next origin at once |
| Deadlines | per attempt (10 min), overall per file (optional), the caller's context |
| Stall guard | no byte for 60 s aborts the attempt; the next resumes |
| Resume | `Range: bytes=<n>-` from the partial file; 206 with a matching `Content-Range` appends, 200 restarts, 416 restarts; bytes of two origins are never mixed; a resumed file that fails the hash restarts once on the same origin |
| Conditional GET | pointers and manifests: `If-None-Match` with the cached ETag; 304 serves the cached copy (still verified) |
| Circuit breaker | per origin: 3 consecutive files that exhausted their transient retries open it for 5 min; a 404 does not count |
| Cache | `<cache>/blobs/sha256-<hex>` (0600 files, 0700 dirs), verified on every hit; a damaged entry is fetched again |

A pointer and its manifest read from a release that changes between the two
requests fail the pin check; the run stops and the next tick starts over.

## 7. Push side

The push half exists and is adopted as is:

| Requirement | Where |
|---|---|
| batch records into chunks by size | `chunk.SplitSegments` within the server's advertised per-segment limits; a 413 halves the refused segment |
| idempotency key per chunk | `report_id` (UUIDv7) + segment number + `Content-Digest`; replays answer 200 and store nothing |
| retries, Retry-After, 429/5xx | `client.PushResultsV2` with the outbox's back-off and circuit breaker |
| disk spool when the platform is unreachable | `pkg/outbox`: written before the first send, AES-256-GCM sealed, 0600/0700, `flock`, byte cap (1 GiB and ≤ half the free space) and age cap (7 days) with oldest-first eviction, dead letters, corrupt-file quarantine |
| resume after restart | `V2Progress` persisted by the outbox: acknowledged segments are not resent |
| metrics | `openctem_sensor_outbox_*` (pending, bytes, oldest age, evicted, delivered, attempts) and the heartbeat's `outbox` block |
| platform accepts chunks idempotently | RFC-026 segment store + commit; RFC-005 asynchronous ingest |

Remaining work is adoption: every collector that pushes to the platform
(including asset collectors run outside the sensor runtime) goes through
`client.PushResultsV2` with the outbox enabled, never a direct POST.

## 8. Observability

- Fetcher counters (`<ns>_transfer_*_total{feed}`): files fetched, bytes,
  cache hits, 304s, retries, resumes, fall-backs, failures, circuit skips.
- Consumer counters (`<ns>_bundle_*_total{feed}`): runs, bundles completed,
  resumes, chunks applied, chunks failed, records applied, refusals
  (signature, pin, cap, expiry, rollback, chunk mismatch).
- Structured logs (`log/slog`): feed, origin label, file name, sequence,
  chunk index, sizes, attempt, wait, error. Never record content, never URLs
  with credentials (refused at configuration).
- The platform's feed status (admin feed page, existing sync status rows)
  shows applied sequence, bundle in progress with `next_chunk / chunks`, last
  error and last success.

## 9. Security

**9.1 Integrity and authenticity.** The pointer is signed and pins each
manifest by sha256 and size; each manifest is signed and pins every chunk.
One signature covers every byte. Mirrors, caches and the local directory
are untrusted transport: they can withhold, not alter.

**9.2 Rollback and freeze.** A sequence older than the applied one is
refused; pointers and manifests expire (at most 8 days validity). A mirror
that withholds new releases can delay updates by at most the validity
window; the feed status flags a stale feed (existing `CheckStale`).

**9.3 Cross-feed and cross-type substitution.** Payload types carry the feed
name and the object type; the payload repeats the feed; a vulnerability
feed signature never verifies as a program feed pointer, nor a pointer as a
manifest.

**9.4 Resource exhaustion.** Caps on pointer (64 KiB), key set (64 KiB),
manifest (8 MiB), chunk count (8 192), chunk compressed size (32 MiB),
uncompressed size (256 MiB, and exactly the declared size), records per
chunk, line length (4 MiB), total bytes (8 GiB). Downloads never write past
the declared size. Each feed may lower them.

**9.5 Parsing.** Chunks are hashed before they are parsed. Per-record
validation stays in the feed's domain parser (strict decoding, the existing
record checks); one bad record fails its chunk's transaction.

**9.6 Tenant isolation.** Feed data (CVE corpus, public programs) is
platform-wide catalog data: `feed_checkpoints` has no `tenant_id` by design,
and nothing tenant-specific is ever written by a feed import. Per-tenant
effects (matches, subscriptions) run after import in the existing
tenant-scoped services. Per-tenant data travels only on the push path,
whose tenant comes from the authenticated sensor identity (`agt.TenantID`),
never from the payload.

**9.7 Network.** Every request through the SSRF-guarded client; file names
are a single path element, so a name can never escape a local origin or the
cache; origins are operator configuration (env), never request input.

**9.8 Local files.** Cache and checkpoint files are 0600 in 0700
directories. Feed data is public, so the pull cache is not encrypted. The
push spool may hold tenant findings and is encrypted (outbox).

## 10. Compatibility and migration

Minimal back-compat (one release):

1. Producers write v2 files **next to** the v1 files in the same release
   (`latest.v2.dsse.json` beside `latest.dsse.json`; chunk names never
   collide with v1 names).
2. Importers prefer v2 when `latest.v2.dsse.json` exists and fall back to
   the v1 path otherwise; the first v2 import continues from the sequence
   the v1 path applied (the checkpoint migration copies it).
3. After one release with both, producers stop writing v1 and the importers'
   v1 code (`pkg/vulnbundle`, the v1 parts of `pkg/programfeed`) is removed.
   Upgrade note: a platform older than step 2 must upgrade before step 3.

The record schemas (`openctem.programfeed/v1` records, the vulnerability
feed records) do not change; only the container does.

## 11. Implementation plan and follow-up PRs

| # | Repo | PR | Content |
|---|---|---|---|
| P0 | sdk-go | #233 | `pkg/transfer`, `pkg/transfer/bundle`: format, writer, consumer, fetcher, file checkpoint, fault-injection tests |
| F1 | programfeed | `feat(bundle): emit format v2 next to v1` | `bundle.Write` also runs `bundle.Writer` (streams `programs`, `changes`; `meta` = sources, stats, collector) and `WritePointer`; publish workflow uploads the chunk files; golden v2 testdata |
| F2 | vulnfeed | `feat(bundle): emit format v2 next to v1` | same, streams `products`, `vulns`, `ranges` |
| F3 | openctem api | `feat(feeds): feed_checkpoints table and Postgres checkpoint` | migration `feed_checkpoints (feed text PK, applied_sequence, in_progress_sequence, kind, manifest_sha256, next_chunk, updated_at)`, backfilled from the existing per-feed applied sequence; `postgres.FeedCheckpoint` implementing `bundle.Checkpoint`; api `go.mod` requires sdk-go |
| F4 | openctem api | `feat(programfeed): import v2 bundles chunk by chunk` | `Applier` over the catalog repository (per-chunk transaction, `feed_sequence` guard, snapshot sweep in `Complete`); `feedsign` as `Trust`; origins from `PROGRAM_FEED_URL` + `PROGRAM_FEED_MIRRORS` + the uploaded bundle directory; metrics registered |
| F5 | openctem api | `feat(vulnfeed): import v2 bundles chunk by chunk` | same for the CVE corpus (`EmptiedRanges` work moves to `Complete`) |
| F6 | openctem api | `feat(feeds): feed status shows chunk progress` | admin feed status: in progress `next_chunk/chunks`, resumes, last error |
| F7 | programfeed, vulnfeed | `chore(bundle): stop writing v1` | after one release with both |
| F8 | openctem api | `chore(feeds): remove the v1 bundle readers` | after F7; upgrade note |
| F9 | sdk-go, sensor | `docs: collectors push through PushResultsV2 + outbox` | audit every pusher (asset collectors, importers run as tools) for direct POSTs |
| F10 | sdk-go | `refactor(contentcache): download packs through transfer.Fetcher` | content packs get resume and mirrors for free |

F1/F2 and F3 are independent; F4 needs F1 and F3; F5 needs F2 and F3.

## 12. Decisions

| # | Decision | Adopted |
|---|---|---|
| D1 | One shared layer in sdk-go; the api takes a dependency on sdk-go for it (the packages are stdlib + `httpsec`/`jobsig` + Prometheus) | yes |
| D2 | Flat release layout, chunks named `sha256-<hex>.jsonl.gz` | yes |
| D3 | Content-defined chunk boundaries from record ids (target 2 000 records, cap 48 MiB uncompressed) | yes |
| D4 | The SDK verifies through a `Verifier`/`Trust` interface; each feed keeps its key set rules (`feedsign`); the SDK ships a plain Ed25519 DSSE signer and verifier on the `jobsig` envelope | yes |
| D5 | Checkpoint = applied sequence + bundle in progress + next chunk; one platform table `feed_checkpoints` for all feeds | yes |
| D6 | A delta is applied only on top of exactly its base; anything else takes the snapshot | yes |
| D7 | Push side: adopt protocol v2 segments + outbox as the chunker and spool; no second spool | yes |
| D8 | v1 and v2 side by side for one release, then v1 removed | yes |

## 13. Alternatives considered

- **Whole-file download with Range resume only.** Fixes dropped
  connections, not crash-mid-apply, memory, or re-download of unchanged
  data.
- **Fixed-size chunks.** Simpler, but one insertion shifts every following
  boundary and defeats reuse across releases.
- **A database-backed spool on the platform for pull data.** Unneeded: the
  content-addressed cache plus the checkpoint give resume without storing
  feed data twice.
- **Signing each chunk.** One manifest signature over chunk hashes gives the
  same guarantee with one verification and no per-chunk envelope.
