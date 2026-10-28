# Feed transfer

Design: [RFC-072](../rfcs/RFC-072-chunked-feed-transfer.md). Code: ctis
`transfer` (fetcher) and `transfer/bundle` (format, writer, consumer), one Go
module of their own, `github.com/openctemio/ctis/transfer` (tags
`transfer/vX.Y.Z`). It is a contract: the feed publishers and the api share
it, and the api depends on no sensor SDK module at all
([RFC-094](../rfcs/RFC-094-platform-contracts-only.md)). It moved unchanged
from `github.com/openctemio/sdk-go/pkg/transfer` v0.1.0; a golden test in ctis
pins the published bytes to that version.
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

### KEV and EPSS (signed side manifest)

The collector publishes the CISA KEV catalog and the EPSS scores next to
each release as a signed side manifest, `intel.manifest.dsse.json`
(`pkg/vulnbundle/intel.go`; format in the collector's README, "KEV and EPSS
side manifest"). The corpus format is untouched, so an older platform ignores
the files. After the corpus, in the same run (also when the corpus is
already up to date), `internal/app/vulnfeed/intel.go`:

1. verifies the manifest against the pinned root's key set and the applied
   sequence (an old manifest cannot be replayed with a new release), then
   each stream: a safe name, its own entries file, a data date not in the
   future, a fetch time inside the release's window;
2. skips (and lists in the status row's `intel_skipped`) a stream name it
   does not know: the manifest is signed, so skipping is safe and later
   signals add streams without a lockstep release;
3. per known stream, asks the intel service whether the stream is **newer
   than the data held**. If not, nothing is downloaded: only the stream's
   freshness (`bundle_fetched_at`, when the collector last read the source)
   is recorded. If so, the entries file is checked against the signed size
   and SHA-256 and every line is parsed strictly (ids ascending and unique,
   scores between 0 and 1, the record count as the manifest states);
4. applies it through `threat.IntelService.ApplyBundleKEV` /
   `ApplyBundleEPSS`: the data date must be newer than the date of the data
   held **from either path** (KEV by time, EPSS by day), so a replayed,
   resent or carried-forward older copy never rolls the catalog back and a
   bundle copy never overwrites a newer direct fetch; a snapshot under 90 %
   of the stored record count is refused as truncated; KEV removals stay
   behind the 25 entries / 2 % prune guard shared with the direct sync.

Then the same post-sync work as after a direct sync runs through one
function, `controller.IntelSweeper.Run` (queue the open findings whose intel
moved, refresh stored EPSS, reconcile KEV flags, report material changes to
the vulnerability event log). A refused stream is recorded as
`bundle_error` in that source's status row and never undoes the corpus
import; the other stream and the next run are unaffected.

Per source, the sync status row's metadata says which path supplied the data
held and how current the bundle's copy is: `delivered_via` (`bundle` or
`direct`), `intel_as_of` (data date), `bundle_fetched_at`,
`bundle_sequence`, `bundle_error`.

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
