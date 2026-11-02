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

#### Direct fetch as a fallback

The platform also fetches KEV (hourly, conditional request) and EPSS (daily)
from CISA and FIRST itself. Two console settings (`threat_intel.source`,
System > Threat intelligence, `/admin/settings/threat-intel-source`; super
admin, step-up, audited) decide how the two paths combine:

| Setting | Effect |
|---|---|
| source `direct` (default), direct fetch `auto` (default) | the own fetch runs on its schedule and supplies the data; the release copy is applied when its data date is newer |
| source `bundle`, direct fetch `auto` | the release supplies the data; the scheduled own fetch runs only when the release's copy was last read by the collector more than 6 hours ago (KEV) or 48 hours ago (EPSS), or never (`bundle_fetched_at`, not the publisher's data date, which can be days old while the data is current); it records `delivered_via = direct`, and the newer-data rule lets the release win again once it catches up |
| direct fetch `off` | the platform never calls CISA or FIRST (the scheduled and the manual sync both refuse); the release is the only supplier and a stale copy shows as stale |

The default stays `direct` until the publisher has released hourly for seven
days without a gap. Then an administrator sets source `bundle`: the page shows
per feed when the collector last read the source and whether the release's copy
is fresh, which is the check to make first. A withheld release (a freeze)
degrades to the own fetch, not to stale data, and the stale alert still fires.
The sync status of each feed reports `delivered_via` and `data_as_of`.

## Relay: feeds through a platform sensor (no outbound access)

Design: [RFC-142](../rfcs/RFC-142-feed-relay.md). Code: `internal/app/feedrelay`
(rounds, spool, controller `feed-relay`, status), `internal/app/vulnfeed/relay.go`
(the planner), `internal/infra/postgres/feed_relay_round_repository.go`, sdk-go
`pkg/feedrelay` (the sensor side).

In relay mode (`GET/PUT /api/v1/admin/settings/feed-relay`; setting
`egress.mode.feeds` = `{mode, sensor_ids}`, the mode and one to three designated
relay sensors saved in one write; super admin, step-up, audited) the platform
makes no outbound feed request:

| Feed | In relay mode |
|---|---|
| vulnerability feed (corpus, KEV/EPSS side manifest, aliases, vulnerability ids) | relayed from `VULNFEED_BASE_URL` (not the direct-mode mirrors); the importer reads the relay working directory as its only origin |
| KEV / EPSS direct fetch | off (the source policy is "bundle, direct fetch off") |
| version check (release feed) | relayed; applied with origin `relay` (the same file again each day is not an error); the online check does not run |
| program feed URLs | not fetched (a `PROGRAMFEED_DIR` still is); listed as `not_relayed` in the status |

Defaults: a new compose install with the bundled sensor starts in relay mode
(`bootstrap-admin sensor-token -feed-relay` stores relay mode only when the
setting was never written, and the sensor that enrolls with that token is
designated once it reports `feed.relay@1`). Existing installations stay
`direct`: the feed relay migration records `direct` for a database that already
has users. There is never an automatic fallback to direct: a setting that
cannot be read counts as relay.

How a cycle runs (the replica holding the `feed-relay` controller lease, every
30 s):

1. **head**: a round asks for the key set, the pointer and the side manifests
   (unpinned, capped).
2. **plan**: after a round is delivered, the lease holder copies the spool into
   its working directory and the planner verifies the key set against the
   pinned root and its floor, the pointer and the manifests, and asks for what
   the import will need and the spool lacks: the manifest the pointer pins, the
   chunks (delta on its base, else snapshot), the side data files, each
   **pinned** by SHA-256 and size, at most 64 files or 192 MiB a round.
3. **import**: nothing missing, the importer runs on the working directory with
   every check of a bundle directory; spool rows and local files the current
   release no longer names are removed.
4. The next cycle starts after the feed's interval (20 min, release feed 24 h);
   a failed, refused or expired round backs off (at most 10 min).

Import is single-runner: the controller is exclusive (Postgres lease) and the
importer takes its own run guard; no other lock is needed. The controller's
timeout is the direct import's (45 min) so a first relayed snapshot is not
cancelled.

**Rounds and claims.** A round is a platform-wide row `feed_relay_rounds` (no
tenant), created unclaimed. `GET /api/v2/sensor/feed-relay/next` claims the
oldest open round for the calling sensor (`FOR UPDATE SKIP LOCKED`) and signs
it with the job signer as a `feed_relay` statement (platform tenant id,
instance scope, the feed origins as targets, which the signer checks against
`SIGNER_FEED_ORIGINS`). A claim with nothing uploaded for 10 minutes, or held
by a sensor no longer designated, may be claimed by another designated sensor:
two or three relays give failover. The claimer asking again gets its own round
back (a restarted relay resumes it). Uploads and `done` bind to the claimer.
A round the signer refuses is closed `failed` with `signer_refused` and the
signer's reason. With no round the answer is 204 with `Retry-After`: 15 s
while a cycle waits for its next plan, 60 s otherwise, 10 min for an eligible
sensor that is not designated (or direct mode). Only active instance-scope
sensors reporting `feed.relay@1` reach the routes; an organization's sensor
gets 403.

**Spool.** `PUT .../{round}/files/{name}` needs Content-Length and a sha-256
Content-Digest. The body is read under the file's cap (at most 32 MiB),
hashed, checked against the declaration and the round's pin, then stored in
`feed_relay_files` (one row per feed and name, shared by every API replica) in
one transaction that also checks the round is open and claimed by the
uploader, one upload per name per round (the same bytes again is a no-op), the
round's budget (256 MiB) and the spool quota (512 MiB; `spool_full` is
recorded on the round). A tampered file never enters the spool. The lease
holder copies rows into `<FEED_CACHE_DIR>/relay/<feed>` (pod-local, rebuilt
from the table after a restart, every row's digest re-checked) before it plans
or imports. Steady state is about 70 MB; the spool is emptied after seven days
in direct mode. Backups may skip the table's data (re-fetchable).
`POST .../{round}/done` keeps only rows for the round's own files, with
bounded codes.

**Status** (`GET /api/v1/admin/settings/feed-relay`, any administrator): the
mode, the designated sensors (online, can relay, last served, bytes today) and
per feed the applied sequence, the release's creation time and its age, the
round in progress (files and bytes delivered of wanted, claimer), and a
stale reason from a fixed list: `no_relay_designated`, `relay_offline` (no
designated sensor seen for 10 min), `signer_refused`, `sensor_refused`,
`upstream_missing` (the relay got 404), `nothing_delivered`, `pin_mismatch`,
`verify_failed`, `rollback_refused`, `plan_failed`, `import_failed`,
`round_expired`, `spool_full`.

A bundle directory (`VULNFEED_BUNDLE_DIR`) or a missing job signer locks relay
mode off.

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
