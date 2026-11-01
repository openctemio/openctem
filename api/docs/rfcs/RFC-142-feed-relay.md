# RFC-142: Feed relay: signed feeds through a platform sensor, zero platform egress

| | |
|---|---|
| Status | Accepted (2026-11-01). Implemented: the job signer's feed relay rules (`SIGNER_FEED_ORIGINS`); the platform relay channel (rounds, spool, planner for the vulnerability feed with its side files and the release feed, the `relay` mode of the feed egress category with the KEV/EPSS, version check, program feed and CTEM-ID fetchers off, admin status and setting); the sensor side in sdk-go (`feed.relay@1`). Designed: the sensor's opt-in wiring, the console card, CTEM-ID as a signed stream, program feed and content packs through the relay |
| Scope | api (signer, relay channel, importers, console), sdk-go, sensor, vulnfeed (CTEM-ID stream, later) |
| Related | RFC-040 (signed jobs), RFC-072 (chunked feed transfer), RFC-100 (shared sensors), RFC-105 (version check) |

## 1. Summary

A platform usually sits in an internal network. Every feed it reads (the vulnerability feed with its
KEV and EPSS side manifest, the program feed, the release feed of the version check, the CTEM-ID
catalog, platform content packs) must be able to reach it through a sensor that has internet access,
so that the platform itself needs no outbound access at all.

The relay is a pipe for signed files and adds no trust. The platform decides which files of a feed
it needs; a designated platform-owned sensor downloads exactly those files from fixed feed origins
and streams them back; the platform writes them into a local relay spool and runs the existing
importers with that directory as their only origin, the same path as a bundle directory. Every
signature, key-set floor, sequence, expiry, size and digest check runs unchanged. A relay can
withhold files; it cannot get anything applied that the feed's pinned root did not sign.

## 2. Design

### 2.1 Relay rounds

- A round is a platform-wide row (no organization): `{id, sensor, feed, origins, files[{name,
  sha256?, size?, max_bytes}], expires_at, status}`. It is signed by the job signer as an
  `openctem.job/v1` statement with `command_type` `feed_relay`, the platform tenant id (the nil
  UUID), `sensor_scope` `instance`, no tool, and the feed origins as targets
  ([job-signing.md, Feed relay](../architecture/job-signing.md#feed-relay)).
- The sensor polls `GET /api/v2/sensor/feed-relay/next`, verifies the statement with the job
  signing keys it pins (sequence, nonce, payload digest), downloads each file from
  `<origin>/<name>` (single path segment names), and uploads it with
  `PUT /api/v2/sensor/feed-relay/{round}/files/{name}` (Content-Length and Content-Digest
  required, streamed to disk, hashed, size capped, a pinned file refused on a digest mismatch before
  it enters the spool), then reports `POST /api/v2/sensor/feed-relay/{round}/done`.
- The platform plans per feed: first the key set, pointer and side manifests; after verifying them,
  the manifests and side data files they pin; after verifying the manifests, the chunks the importer
  will need that the spool does not hold. When nothing is missing, the importer runs on the spool.

### 2.2 Who may relay

Only a platform-owned (instance-scope) sensor that the super administrator designated, whose host
operator opted in (`SENSOR_FEED_RELAY=1`, shared mode only). Never an organization's sensor:

- API: rounds are offered only to the designated instance-scope sensor; uploads bind to the round's
  sensor.
- Signer: the platform tenant id only for `feed_relay`, which requires `sensor_scope` `instance`.
- Sensor (sdk-go): a statement with the platform tenant id is accepted only in shared mode and only
  for `feed_relay`; the command poller never runs `feed_relay`.

### 2.3 Where the relay may download from

The statement's targets are the feed origins. The signer signs only origins in its allowlist
(`SIGNER_FEED_ORIGINS`), the sensor fetches only origins in its own (the official origins plus
`SENSOR_FEED_RELAY_ORIGINS`), through its SSRF guard (public addresses only, redirects re-checked).
A mirror therefore needs two keys held outside the API.

### 2.4 Relay mode on the platform

The feed egress category has the modes `direct` (default) and `relay`. In `relay` the platform
makes no outbound feed request: the vulnerability feed and its KEV/EPSS side manifest come from the
spool, the direct KEV/EPSS fetchers are off, the release feed comes through the relay, program feed
URL origins are dropped, and the CTEM-ID refresh is skipped until CTEM-ID is a signed stream of the
vulnerability feed. A configured bundle directory locks relay mode off. The console shows the relay
sensor, the last round and delivery per feed, and the importer's verification result.

## 3. Threat model

| Threat | Control |
|---|---|
| The relay, its network or a mirror alters data | importers verify against the pinned root as for a bundle directory; pinned files are hash-checked on receipt; unpinned files are verified before use |
| Rollback or replay | importer sequence and expiry, KEV/EPSS data date; a replayed round is refused by the sensor (sequence, nonce) and the API (round bound to sensor, single use, expiry) |
| Freeze | per-feed staleness and alerts as today; round failures on the console; direct mode and bundle directories stay available |
| A compromised API points the relay at internal or arbitrary URLs | signer and sensor origin allowlists; single-segment names; sensor SSRF guard |
| An organization's sensor used as relay | refused by the API, the signer and sdk-go (§2.2) |
| Upload exhaustion or path traversal | per-file and per-round caps, Content-Length required, streamed to disk, strict name grammar, names listed in the round |
| Information leak to feed hosts | plain GET with no installation, tenant or count data |

AuthZ: status for any platform administrator; mode and designated sensor for the super
administrator with step-up and a critical admin audit row. No tenant route changes; feed data is
platform catalog data, written only by verified imports.

## 4. Plan

1. Signer feed relay rules (this change).
2. sdk-go `feed.relay@1` (poll, verify, guarded download, streamed upload) and the sensor's opt-in.
3. API relay channel, spool, planner (vulnerability feed with side files, release feed), the relay
   mode, console status.
4. Later: CTEM-ID as a signed stream of the vulnerability feed, program feed and content packs
   through the relay, install toggles, an object-storage spool for several API replicas.
