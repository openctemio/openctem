# Version check

Design and decisions: [RFC-105](../rfcs/RFC-105-version-check-and-usage-telemetry.md).

The platform console tells platform administrators when a newer OpenCTEM
release exists and, above all, when the running release is affected by a
published security advisory. The instance learns this from one public,
signed, static file — the **release feed** — and compares it with its own
version locally. Nothing about the instance is sent.

## What leaves the server

| | |
|---|---|
| Request | `GET` of `VERSION_CHECK_URL`, once a day (up to four hours of random delay; the first check 5 to 60 minutes after start-up; weekly after three failed checks in a row) |
| Headers | `User-Agent: openctem-version-check/1`, `Accept: application/json`. No version, no instance id, no cookies, no `Referer`, no query string |
| Body | none |
| Who sees it | the host of the file (by default GitHub, which serves release assets) sees the source IP of one anonymous download a day; OpenCTEM receives only the aggregate download count GitHub shows for an asset |
| Turn it off | `VERSION_CHECK_ENABLED=false`: no request at all. The console still shows a feed imported by hand |

There is no usage reporting of any kind. Usage telemetry is designed in the
RFC as deferred and opt-in only; nothing sends it.

## Trust

The file `openctem-releases.json` holds two DSSE envelopes in the shared
signed-feed format (`pkg/feedsign`):

1. a **key set** (`openctem.io/release-keyset/v1`) signed by an offline root
   key, valid at most 180 days, versioned;
2. the **feed** (`openctem.io/release-feed/v1`) signed by an online key of
   that key set: a sequence (the issue time in Unix seconds), an issue and an
   expiry time (at most 45 days apart), the releases and the advisories.

The instance trusts only the root key ids pinned in the binary
(`releasefeed.PinnedRoots`); there is no configuration override. It refuses:

- a key set from another root, of another kind, expired, or with a version
  below the one it applied (a revoked online key cannot come back);
- a feed not signed by a key of that key set, of another payload type, with a
  sequence below the one it applied (rollback), expired or issued in the
  future;
- any field out of bounds: versions must be `vX.Y.Z`, severities
  low/medium/high/critical, titles at most 200 characters without control
  characters, links HTTPS under `github.com/openctemio/`, `openctem.io` or
  `docs.openctem.io`, at most 200 releases and 200 advisories, at most 256 KiB
  in all, no unknown fields.

Anything refused is discarded and the previous state kept. The feed is
display-only: the instance never downloads or runs anything because of it.

Until a root is pinned in the build, the check is inert (no request) and the
console says the feed cannot be verified.

## Comparison

- An advisory affects version `v` when `introduced <= v < fixed_in`
  (`introduced` optional).
- A development build `vX.Y.Z-dev+sha` is compared as `vX.Y.Z`; a release
  candidate `vX.Y.Z-rc.N` as itself, so the final release counts as newer; a
  build with no version (`dev`) is not compared.
- A stored feed past its expiry is shown as out of date with its date.

## Air-gapped and offline instances

An instance without internet access records the failure (`unreachable`),
logs one line per check and backs off to weekly. A super administrator can
import the same file in the console (System > Software updates > Import):
download `openctem-releases.json` from the latest release on a connected
machine, carry it in, upload it. It goes through exactly the same
verification, including rollback and expiry. Set `VERSION_CHECK_ENABLED=false`
to stop the outbound attempt entirely.

A mirror: point `VERSION_CHECK_URL` at an internal copy (http or https; the
signature carries the trust). The fetch uses the SSRF-guarded client
(`pkg/httpsec`), so a mirror on a private address also needs the instance's
private egress allowlist (`OPENCTEM_HTTPSEC_*`). Outbound HTTP proxies are not
used by this client.

## Console

- A banner on every console page: "Update available" (information) or
  "Security release: upgrade" (highlighted, with the highest severity and the
  version that fixes it), linking to the Software updates page.
- System > Software updates: running version, latest release, releases newer
  than the running one, the advisories that affect it, where the information
  came from (online or imported) and when, the last check's outcome and the
  next check, and the import.
- Organization users see nothing.

| Route | Gate |
|---|---|
| `GET /api/v1/admin/version-check/` | any administrator |
| `POST /api/v1/admin/version-check/import` | super administrator + console step-up; high-severity admin audit row (`version_check.feed_imported`), refused imports included |

## State

One row in `version_check_state` (migration `002600`): the last verified feed,
its origin, the applied sequence and key set version, the last attempt, the
last failure code, the consecutive failure count and the next check time.
API replicas share it; a conditional update elects the one replica that
fetches a due check. Instance-level; no tenant data.

## Publishing the feed

`api/cmd/release-feed` creates keys, signs key sets and builds the file:

```bash
# Offline machine (root), once and on every key rotation:
go run ./cmd/release-feed keygen -out release-root.key
go run ./cmd/release-feed keygen -out release-online.key
go run ./cmd/release-feed keyset -root release-root.key -online <online public key hex> \
    -version 1 -days 180 -out keyset.dsse.json

# Release pipeline:
gh release list --json tagName,publishedAt,isDraft,isPrerelease --limit 200 > releases.json
go run ./cmd/release-feed build -keyset ../.github/release-feed/keyset.dsse.json \
    -key-env RELEASE_FEED_SIGNING_KEY -releases releases.json \
    -advisories ../.github/release-feed/advisories.json -out openctem-releases.json
go run ./cmd/release-feed verify -root <root key id> openctem-releases.json
```

The workflow `.github/workflows/release-feed.yml` runs on every release (called
by `release.yml`), every week (so the feed never expires between releases)
and by hand. It uploads the file to the latest release, which is what the
default URL `https://github.com/openctemio/openctem/releases/latest/download/openctem-releases.json`
serves. It skips with a warning while the key set file or the
`RELEASE_FEED_SIGNING_KEY` secret is missing, so a release never fails on it.

Advisories: add an entry to `.github/release-feed/advisories.json` when an
advisory is published (with or after the fixing release, never before), then
run the workflow by hand.

### Setup (maintainers)

1. On an offline machine, create the root and online keys and sign the key
   set (commands above). Keep the root offline.
2. Commit `.github/release-feed/keyset.dsse.json` and add the root key id to
   `releasefeed.PinnedRoots` in the same pull request.
3. Store the online key seed (the content of `release-online.key`) as the
   secret `RELEASE_FEED_SIGNING_KEY` of the GitHub environment `release-feed`,
   restricted to `main` and `v*` tags.
4. Before the key set expires, sign a new one with a higher version and
   commit it. To retire a leaked online key, sign a new key set version
   without it and rotate the secret.

## Key files

- `api/pkg/releasefeed/` — format, verification, comparison
- `api/pkg/feedsign/` — shared envelope and key set checks
- `api/internal/app/versioncheck/` — fetcher, schedule, import, console view
- `api/internal/infra/controller/version_check.go` — hourly wake-up
- `api/internal/infra/postgres/version_check_repository.go` — the state row
- `api/internal/infra/http/handler/admin_version_check_handler.go` — console routes
- `api/cmd/release-feed/` — key and feed tooling
- `.github/workflows/release-feed.yml`, `.github/release-feed/` — publishing
