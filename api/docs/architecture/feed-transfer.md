# Feed transfer

Design: [RFC-070](../rfcs/RFC-070-chunked-feed-transfer.md). Code: sdk-go
`pkg/transfer` (fetcher) and `pkg/transfer/bundle` (format, writer,
consumer).

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
