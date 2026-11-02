# RFC-142: Feed relay: signed feeds through a platform sensor, zero platform egress

| | |
|---|---|
| Status | Accepted (2026-11-01, revised 2026-11-02). Implemented: the job signer's feed relay rules (`SIGNER_FEED_ORIGINS`); the platform relay channel (claimed rounds, Postgres spool, planner for the vulnerability feed with its side files and the release feed, the `relay` mode of the feed egress category with one to three designated relay sensors, the KEV/EPSS, version check and program feed fetchers off, admin status and setting, relay mode by default on a new compose install with the bundled sensor); the sensor side in sdk-go (`feed.relay@1`, on by default on a shared sensor). Designed: the console card, Helm and installer kit toggles, alerts, program feed and content packs through the relay |
| Scope | api (signer, relay channel, importers, console), sdk-go, sensor |
| Related | RFC-040 (signed jobs), RFC-072 (chunked feed transfer), RFC-100 (shared sensors), RFC-105 (version check) |

## 1. Summary

A platform usually sits in an internal network. Every feed it reads (the vulnerability feed with its
KEV and EPSS side manifest, the program feed, the release feed of the version check, platform
content packs) must be able to reach it through a sensor that has internet access,
so that the platform itself needs no outbound access at all.

The relay is a pipe for signed files and adds no trust. The platform decides which files of a feed
it needs; a designated platform-owned sensor downloads exactly those files from fixed feed origins
and streams them back; the platform stores them in the relay spool (a Postgres table every API
replica shares), the replica that holds the controller lease copies them into a local working
directory and runs the existing importers with that directory as their only origin, the same path
as a bundle directory. Every
signature, key-set floor, sequence, expiry, size and digest check runs unchanged. A relay can
withhold files; it cannot get anything applied that the feed's pinned root did not sign.

## 2. Design

### 2.1 Relay rounds

- A round is a platform-wide row (no organization): `{id, feed, origins, files[{name,
  sha256?, size?, max_bytes}], expires_at, status, claimed sensor}`, created unclaimed. It is signed by the job signer as an
  `openctem.job/v1` statement with `command_type` `feed_relay`, the platform tenant id (the nil
  UUID), `sensor_scope` `instance`, no tool, and the feed origins as targets
  ([job-signing.md, Feed relay](../architecture/job-signing.md#feed-relay)).
- The sensor polls `GET /api/v2/sensor/feed-relay/next`, which claims the oldest open round for it
  (`FOR UPDATE SKIP LOCKED`) and signs it, verifies the statement with the job signing keys it pins
  (sequence, nonce, payload digest), downloads each file from `<origin>/<name>` (single path
  segment names), and uploads it with `PUT /api/v2/sensor/feed-relay/{round}/files/{name}`
  (Content-Length and Content-Digest required, at most 32 MiB, hashed, a pinned file refused on a
  digest mismatch before it enters the spool), then reports
  `POST /api/v2/sensor/feed-relay/{round}/done`. With no round the answer is 204 with a
  `Retry-After` the sensor honours.
- Failover: a claim with nothing uploaded for 10 minutes, or held by a sensor no longer designated,
  may be claimed by another designated sensor. Uploads and `done` bind to the claimer.
- A round the job signer refuses is closed `failed` with `signer_refused` and the signer's reason,
  shown in the console; the cycle backs off.
- The platform plans per feed: first the key set, pointer and side manifests; after verifying them,
  the manifests and side data files they pin; after verifying the manifests, the chunks the importer
  will need that the spool does not hold. When nothing is missing, the importer runs on the working
  directory; spool rows the current release no longer names are pruned.

### 2.1a Spool and several API replicas

Uploads arrive on any API replica; planning and import run on the replica holding the `feed-relay`
controller lease. The spool is therefore the table `feed_relay_files` (one row per feed and file
name, bytea, no tenant column). An upload is stored in one transaction that checks the round is
open and claimed by the uploader, one upload per name per round, the round's budget (256 MiB) and
a spool quota (512 MiB). The lease holder copies the rows into `<FEED_CACHE_DIR>/relay/<feed>`
(pod-local, rebuilt after a restart, each row's digest re-checked) before it plans or imports; the
importers and every one of their checks are unchanged. The data is small (about 64 MB to bootstrap,
5 to 10 MB a day, the largest file about 6 MB). Import is single-runner through the controller lease
and the importer's own run guard; there is no other lock. The spool is emptied after seven days in
direct mode.

### 2.2 Who may relay

Only platform-owned (instance-scope) sensors that the super administrator designated: one to three,
each active and reporting `feed.relay@1`, saved in one write with the mode (refused at save time
otherwise). A shared sensor reports `feed.relay@1` by default when it pins a job-signing key; its
host may turn that off (`SENSOR_FEED_RELAY=0`). Rounds are offered only to designated sensors.
Never an organization's sensor:

- API: rounds are offered only to designated instance-scope sensors; uploads bind to the claimer.
- Signer: the platform tenant id only for `feed_relay`, which requires `sensor_scope` `instance`.
- Sensor (sdk-go): a statement with the platform tenant id is accepted only in shared mode and only
  for `feed_relay`; the command poller never runs `feed_relay`; an organization's sensor never
  reports `feed.relay@1`.

### 2.3 Where the relay may download from

The statement's targets are the feed origins. The signer signs only origins in its allowlist
(`SIGNER_FEED_ORIGINS`), the sensor fetches only origins in its own (the official origins plus
`SENSOR_FEED_RELAY_ORIGINS`), through its SSRF guard (public addresses only, redirects re-checked).
A mirror therefore needs two keys held outside the API. The platform's relay origin for the
vulnerability feed is `VULNFEED_BASE_URL` only; the mirrors of direct mode (`VULNFEED_MIRRORS`) are
not relay origins, since a round naming an origin outside the signer's allowlist is refused.

**No exfiltration channel.** The relay is GET-only on path-pinned origins with names the platform
cannot use to carry data (128 characters of `[A-Za-z0-9._-]`, no body, no headers chosen by the
API). A TLS-passthrough gateway to the feed hosts was rejected for feeds: it would give a compromised
API a two-way channel to every allowlisted host, which zero egress is meant to remove.

### 2.4 Relay mode on the platform

The feed egress category has the modes `direct` and `relay`. In `relay` the platform makes no
outbound feed request: the vulnerability feed and its KEV/EPSS side manifest come from the relay,
the direct KEV/EPSS fetchers are off, the release feed comes through the relay, and program feed
URL origins are not fetched (listed as not relayed). A configured bundle directory or a missing job
signer locks relay mode off.

Defaults: a new compose install with the bundled sensor starts in relay mode (the install step
`bootstrap-admin sensor-token -feed-relay` stores it only when the setting was never written, and
the sensor that enrolls with the install's token is designated once it reports `feed.relay@1`).
Existing installations stay `direct` (the migration records it for a database that has users).
There is never an automatic fallback to direct; an unreadable setting counts as relay.

The console status shows per feed the applied release and its age, the round in progress (files and
bytes delivered, claimer) and one stale reason from a fixed list (`no_relay_designated`,
`relay_offline`, `signer_refused`, `sensor_refused`, `upstream_missing`, `nothing_delivered`,
`pin_mismatch`, `verify_failed`, `rollback_refused`, `plan_failed`, `import_failed`,
`round_expired`, `spool_full`), and the relay sensors (online, last served, bytes today).

## 3. Threat model

| Threat | Control |
|---|---|
| The relay, its network or a mirror alters data | importers verify against the pinned root as for a bundle directory; pinned files are hash-checked on receipt; unpinned files are verified before use |
| Rollback or replay | importer sequence and expiry, KEV/EPSS data date; a replayed round is refused by the sensor (sequence, nonce) and the API (round bound to its claimer, single use, expiry) |
| Freeze | per-feed staleness and alerts as today; round failures on the console; direct mode and bundle directories stay available |
| A compromised API points the relay at internal or arbitrary URLs | signer and sensor origin allowlists; single-segment names; sensor SSRF guard |
| An organization's sensor used as relay | refused by the API, the signer and sdk-go (§2.2) |
| Upload exhaustion or path traversal | 32 MiB per file, 256 MiB per round, 512 MiB spool quota, one upload per name per round, Content-Length required, strict name grammar (also a table constraint), names listed in the round |
| Untrusted bytes stored before verification | the spool holds only files whose size, digest and pin matched; the importer verifies everything again; no tenant data; the table is not part of any tenant export |
| A malicious or failed relay | it can only withhold; another designated relay takes over an idle claim; staleness and the stale reason show it |
| A compromised platform uses the default-on capability | shared sensors GET only compiled official origins (plus host-listed ones) and only designated sensors are offered rounds; the host can turn it off |
| Information leak to feed hosts | plain GET with no installation, tenant or count data |

AuthZ: status for any platform administrator; mode and designated sensors for the super
administrator with step-up and a critical admin audit row (the install step writes its own audit
row, actor `bootstrap`). No tenant route changes; feed data is
platform catalog data, written only by verified imports.

## 4. Plan

1. Signer feed relay rules.
2. sdk-go `feed.relay@1` (poll, verify, guarded download, streamed upload, `Retry-After`), on by
   default on a shared sensor with a pinned key.
3. API relay channel: claimed rounds, Postgres spool, planner (vulnerability feed with side files,
   release feed), the relay mode with one to three relays, status, the new-install default.
4. Later: the console card, Helm and installer kit toggles, alerts (relay offline for an hour,
   `verify_failed`), the program feed and official content packs through the relay (an
   administrator-typed content pack URL is refused in relay mode: upload the file instead), a
   console upload of an offline bundle into the spool.
