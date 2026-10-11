# Feed transfer

Design: [RFC-072](../rfcs/RFC-072-chunked-feed-transfer.md). Code: sdk-go
`pkg/transfer` (fetcher) and `pkg/transfer/bundle` (format, writer,
consumer), one Go module of their own, `github.com/openctemio/sdk-go/pkg/transfer`
(tags `pkg/transfer/vX.Y.Z`). The api requires that module only, never the
whole SDK, so SDK releases and their dependency graph do not reach the api.
The fetcher has no default HTTP client: the api passes `httpsec.SafeHTTPClient`.

Large data crosses the platform boundary in two directions, each through one
code path:

```
 feed collectors                          platform                         sensors / collectors
 (programfeed, vulnfeed)                                                   
  bundle.Writer ──► release / mirrors ──► bundle.Consumer ──► Applier       client.PushResultsV2
                    / local directory     (transfer.Fetcher)  (per-chunk tx,  + outbox (spool)
                                          feed_checkpoints     seq-guarded)        │
                                                                ▲                   │
                                          RFC-026 segments ◄────┴───────────────────┘
                                          RFC-005 async ingest
```

## Pull: signed chunked bundles

A release holds `keyset.dsse.json`, `latest.v2.dsse.json` (signed pointer:
sequence, the snapshot and delta manifest names, sizes and sha256),
`snapshot.v2.manifest.dsse.json` / `delta.v2.manifest.dsse.json` (signed:
streams of chunks with sha256, size, uncompressed size, record count, id
range) and `sha256-<hex>.jsonl.gz` chunks. Chunk boundaries come from record
ids, so unchanged chunks keep their name across releases and are fetched
once.

The importer (one per feed, scheduled, one run at a time) calls
`bundle.Consumer.Run`:

| Step | Check or effect |
|---|---|
| key set | the feed's `Trust` (pinned offline root, key-set version) |
| pointer | signature, feed, expiry (≤ 8 days), sequence > applied (older: refused) |
| choose | the bundle in progress (resume), else the delta on exactly its base, else the snapshot |
| manifest | matches the pointer's pin, signature, caps (chunks, sizes, total) — before any chunk |
| each chunk | fetched (hash and size verified), records streamed and validated by the feed parser, upserted in one transaction guarded by `feed_sequence`, checkpoint saved |
| complete | snapshot: rows of older sequences removed; sequence saved as applied |

`feed_checkpoints` (one row per feed, platform-wide: feed data is catalog
data, never tenant data) holds the applied sequence and the bundle in
progress with its next chunk. A crash or a failed chunk resumes at that
chunk on the next run; a partial bundle is never reported as applied.

The fetcher tries origins in order (release URL, `*_FEED_MIRRORS`, the
uploaded bundle directory) through the SSRF-guarded client: retries with
back-off and jitter, Retry-After, per-attempt deadline, stall guard, Range
resume, ETag, a circuit breaker per origin. Mirrors cannot change content:
everything is pinned by the signed pointer and manifests.

### The vulnerability feed (CVE corpus)

`internal/app/vulnfeed` reads streams `products`, `vulns`, `ranges` (in that
order); a range's record id is `<CVE>#<digest>`, so one CVE's ranges may span
chunks. Each record is validated by `pkg/vulnbundle` (`ParseProduct`,
`ParseVuln`, `ParseRange`), and ids must ascend inside the chunk's declared
range. Per chunk, in one transaction with the checkpoint:

- products resolve to global catalog products and are recorded in
  `cve_feed_products` (bundle key, product, sequence);
- CVE records are upserted with `feed_sequence`;
- ranges are upserted by `range_key` with `feed_sequence`, and must name a
  CVE record and products of the same bundle (written by its earlier chunks,
  so a resumed run needs nothing in memory); ranges of a rejected CVE are
  not kept.

Finishing the bundle (`FinishFeedBundle`, one transaction with the applied
sequence) removes the ranges of an older sequence the bundle replaced: a
snapshot removes every one it no longer holds and withdraws the CVEs it does
not hold; a delta only touches the CVEs it holds. Until then a CVE keeps its
old ranges next to its new ones, so no CVE ever loses ranges mid-bundle. The
removal guard runs here: at most max(500, 2 % of the stored ranges) may be
removed from non-rejected CVEs left without any range; over it the finish is
refused and repeated on each run until a newer release arrives.

The matcher's feed cursor (`cve_records.synced_at`) moves only for CVEs
whose record content changed, that gained a range, or that lost one at
finish, so a release re-evaluates the changed CVEs only.

The v1 reader stays the fallback for one release: when neither the bundle
directory nor the release serves `latest.v2.dsse.json`. Both readers share
the applied sequence (the v1 reader never goes below the checkpoint and
moves it forward; a v2 run first carries the v1 sequence into the
checkpoint) and the key-set version. Origins: the release
(`VULNFEED_BASE_URL` + `/latest/download`), then `VULNFEED_MIRRORS`; with
`VULNFEED_BUNDLE_DIR` only that directory is read.

## Push: segments and the outbox

Sensors and collectors send results with protocol v2 (RFC-026): segments
within the advertised limits, a stable `report_id` and a digest per segment
as the idempotency key, resumable progress. Every report is first written to
the encrypted outbox (0600, byte and age caps, oldest-first eviction), so an
unreachable platform loses nothing within the caps. The platform takes the
tenant from the authenticated sensor, never from the payload.

## Metrics

`*_transfer_*_total{feed}` (files, bytes, cache hits, 304s, retries,
resumes, fall-backs, failures, circuit skips), `*_bundle_*_total{feed}`
(runs, completed, resumes, chunks applied and failed, records, refusals),
and the sensor outbox metrics. Logs carry names, sizes, sequences and
errors, never record content.
