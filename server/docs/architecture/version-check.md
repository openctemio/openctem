# Version check

Design and decisions: [RFC-105](../rfcs/RFC-105-version-check-and-usage-telemetry.md).

The platform console tells platform administrators when a newer OpenCTEM
release exists and, above all, when the running release is affected by a
published security advisory. The same feed tells the instance the newest
release of each first-party sensor product and of the sensor SDK, so a sensor
or SDK release reaches the Sensors page and the install snippets without a
platform release ([RFC-037 §12](../rfcs/RFC-037-versioning-and-release-train.md)). The instance learns this from one public,
signed, static file — the **release feed** — and compares it with its own
version locally. Nothing about the instance is sent.

## What leaves the server

| | |
|---|---|
| Request | `GET` of `VERSION_CHECK_URL`, once a day (up to four hours of random delay; the first check 5 to 60 minutes after start-up; weekly after three failed checks in a row) |
| Headers | `User-Agent: openctem-version-check/1`, `Accept: application/json`. No version, no instance id, no cookies, no `Referer`, no query string |
| Body | none |
| Who sees it | the host of the file (by default GitHub, which serves release assets) sees the source IP of one anonymous download a day; OpenCTEM receives only the aggregate download count GitHub shows for an asset |
| Default | on, in every edition |
| Turn it off | `VERSION_CHECK_ENABLED=false`: no request at all. The console still shows a feed imported by hand |

There is no usage reporting of any kind. Usage telemetry is designed in the
RFC as deferred and opt-in only; nothing sends it.

## Trust

The file `openctem-releases.json` (schema `openctem.io/release-bundle/v2`)
holds the **feed** payload (`openctem.io/release-feed/v1`, base64 of the exact
bytes that were signed) and its keyless Sigstore bundle: a sequence
(the issue time in Unix seconds), an issue and an expiry time (at most 45 days
apart), the releases, the advisories and the components (the newest
release of each first-party sensor product and of the SDK: the
`versions.yaml` section, the version, the publication time, the notes link and,
for an image, its manifest digest).

There is no signing key. The `release-feed` workflow signs the payload with
`cosign sign-blob` using its GitHub OIDC identity; the instance verifies the
bundle **offline** (the platform has no direct egress; the file reaches it
through its feed relay or an import) against the Sigstore trusted root
embedded in the release (`CONTENT_SIGSTORE_TRUSTED_ROOT` names a newer file;
the same root verifies content catalog publishers): the certificate chain to the
Fulcio roots, a transparency log entry (inclusion promise or proof), the
issuer `https://token.actions.githubusercontent.com` and the exact signer
identity `releasefeed.SignerIdentityPattern`: the `release-feed.yml` workflow of
`openctemio/openctem` on `refs/heads/main` or a `refs/tags/vX.Y.Z` tag. There is
no configuration override of the identity. See [signing keys](signing-keys.md).
It refuses:

- a feed whose bundle does not verify for that identity (wrong repository,
  workflow, branch or issuer, a tampered payload, a missing log entry, an
  expired certificate, a foreign trusted root), a signature made before the
  feed's issue time or after its expiry, a sequence below the one it applied
  (rollback), the applied sequence with other content (the SHA-256 of the
  signed payload is stored; the publisher never signs two feeds with one
  sequence), a feed expired or issued in the future;
- any field out of bounds: versions must be `vX.Y.Z`, component names a
  `versions.yaml` section name and digests `sha256:` + 64 hex, severities
  low/medium/high/critical, titles at most 200 characters without control
  characters, links HTTPS under `github.com/openctemio/`, `openctem.io` or
  `docs.openctem.io`, at most 200 releases, 200 advisories and 32 components,
  at most 256 KiB in all, no unknown fields.

Anything refused is discarded and the previous state kept. The feed is
display-only: the instance never downloads or runs anything because of it.
Component versions go into the install commands an administrator copies;
the image repository always comes from the catalog built into the instance,
a learned version is used only when it is not older than the built-in one,
and the digest pins exactly the image the feed was signed for.

Until a Sigstore trusted root loads, the check is inert (no request) and the
console says the feed cannot be verified.

## Comparison

- An advisory affects version `v` when `introduced <= v < fixed_in`
  (`introduced` optional).
- A development build `vX.Y.Z-dev+sha` is compared as `vX.Y.Z`; a release
  candidate `vX.Y.Z-rc.N` as itself, so the final release counts as newer; a
  build with no version (`dev`) is not compared.
- A stored feed past its expiry is shown as out of date with its date.

## Component releases

The feed lists the newest stable release of each first-party component: the
sensor products of `versions.yaml` (`sensor`, `connector-tenable`), the SDK
(`sdk`, openctemio/sdk-go) and the CI runner (`ci`, openctemio/ci, image
`ghcr.io/openctemio/ci`). A component release never needs a change to this
repository:

- **Effective latest.** Each component's `latest` in `versions.yaml` is the
  built-in baseline, the release this platform release was built with. The
  instance overlays the verified feed (`internal/versions`): the learned
  release counts only when it is a `vX.Y.Z` release not older than the
  baseline, so a stale or replayed feed never lowers it and an invalid value
  is dropped. The getters (`Products`, `SensorLatest`, `SDKLatest`,
  `CIRunnerLatest`) return the effective value and are read per use, so a
  feed refresh applies without a restart.
- **CI runner.** The token exchange (refusal below `ci.min`), pipeline health
  ("update available"), the CI alerts job and the console's pipeline snippets
  use the effective CI runner release. `GET /api/v1/ci/settings` answers it as
  `runner_release` (read-only, instance-wide, gated by `ci:read`); the console
  pins it in every snippet and falls back to the release it was built with
  (`CI_RELEASE_FALLBACK`, copied from `ci.latest`) only when the API names
  none. `CI_RUNNER_LATEST_VERSION` set by the operator wins over the feed
  (`none` turns the comparison off).
- **Baseline refresh.** `cut-release.sh` moves every component's `latest`
  forward on the release branch of a train, from the same public release
  lists (`refresh-latest.sh`, the rule of `feed-components.sh`), and copies it
  to its consumers (`sync-versions.sh`); the post-release merge brings it to
  develop. Nobody opens a pull request to bump a `latest`. A component that
  cannot be read keeps its value with a warning. A hotfix keeps its tag's
  values.
- **Compatibility stays in the repository.** `min` (and `sdk.advisories`) is
  this platform's compatibility floor: it never comes from the feed and
  changes only with a protocol change. `ci.min` is v0.4.0, the first runner
  that speaks CTIS 2.0 (this platform refuses CTIS 1.x runners).
- **Release preflight.** A `latest` behind the published release is reported,
  never a blocker. Only compatibility facts block: a `latest` or `min` that
  names a version that is not a published release. A `min` changed since the
  last release is listed for review.

## Air-gapped and offline instances

An instance without internet access records the failure (`unreachable`),
logs one line per check and backs off to weekly. A super administrator can
import the same file in the console (Monitoring > Software updates > Import):
download `openctem-releases.json` from the latest release on a connected
machine, carry it in, upload it. It goes through exactly the same
verification, including rollback and expiry. Set `VERSION_CHECK_ENABLED=false`
to stop the outbound attempt entirely.

A mirror: point `VERSION_CHECK_URL` at an internal copy (https only; the
signature carries the trust, https keeps the request private on the way). The fetch uses the SSRF-guarded client
(`pkg/httpsec`), so a mirror on a private address also needs the instance's
private egress allowlist (`OPENCTEM_HTTPSEC_*`). Outbound HTTP proxies are not
used by this client.

## Console

- A banner on every console page: "Update available" (information) or
  "Security release: upgrade" (highlighted, with the highest severity and the
  version that fixes it), linking to the Software updates page.
- Monitoring > Software updates: running version, latest release, releases newer
  than the running one, the advisories that affect it, where the information
  came from (online or imported) and when, the last check's outcome and the
  next check, and the import.
- Organization users see nothing.

| Route | Gate |
|---|---|
| `GET /api/v1/admin/version-check/` | any administrator |
| `POST /api/v1/admin/version-check/import` | super administrator + console step-up; high-severity admin audit row (`version_check.feed_imported`), refused imports included |

## State

One row in `version_check_state` (migration `002717`, key set version column dropped by `002823`): the last verified feed,
its origin, the applied sequence, the last attempt, the
last failure code, the consecutive failure count and the next check time.
API replicas share it; a conditional update elects the one replica that
fetches a due check. Instance-level; no tenant data.

## Publishing the feed

`server/cmd/release-feed` builds, assembles and verifies the file; the signature
comes from cosign:

```bash
# Release pipeline (the workflow runs these in three jobs):
gh release list --json tagName,publishedAt,isDraft,isPrerelease --limit 200 > releases.json
go run ./cmd/release-feed components > components.txt   # sensor products, sdk-go, the CI runner
bash ../.github/scripts/release/feed-components.sh components.txt > components.json
go run ./cmd/release-feed build -releases releases.json \
    -advisories ../.github/release-feed/advisories.json -components components.json \
    -out feed.json                                       # the exact bytes to sign
cosign sign-blob --yes --bundle feed.sigstore.json feed.json
go run ./cmd/release-feed assemble -feed feed.json -bundle feed.sigstore.json -out openctem-releases.json
go run ./cmd/release-feed verify openctem-releases.json  # offline, embedded trusted root
```

The workflow `.github/workflows/release-feed.yml` runs on every release (called
by `release.yml`, which grants it `id-token: write`), every 6 hours (new sensor, SDK and CI runner releases reach the feed
within that time, and the feed never expires between releases) and by hand.
`feed-components.sh` picks, for each component, the newest stable release
whose image tag is published and records the image digest; it reads only
public release lists and public images, so the sensor, connector,
sdk-go and ci repositories need no step and no secret. A component it cannot resolve fails
the run (the previous feed stays published). Three jobs: `build` (read-only: the payload), `sign` (the only job with
`id-token: write`; it checks out nothing and runs only cosign) and `publish`
(verifies the assembled file with the code of the checkout, as an instance
would, then uploads it). They run only on `main` or a `v*` tag (an explicit
guard; the signer identity names exactly these refs). The file is uploaded to
the latest release, which is what the
default URL `https://github.com/openctemio/openctem/releases/latest/download/openctem-releases.json`
serves. If signing or verification fails the run fails (it runs after the
release job, so the release itself is complete) and the previous feed stays
published.

Refreshing the trusted root: `make -C server sigstore-root-refresh` before each
release (a test fails once the embedded root has nothing valid for the next 30
days).

Advisories: add an entry to `.github/release-feed/advisories.json` when an
advisory is published (with or after the fixing release, never before), then
run the workflow by hand.

### Setup (maintainers)

None: there is no key or secret. The first run of the workflow on `main` after
this change publishes a feed in the new format; check the run summary says
"ok: sequence …, N components" and that
`https://github.com/openctemio/openctem/releases/latest/download/openctem-releases.json`
answers 200. Optionally keep the `release-feed` environment restricted to
`main` and `v*` (the sign job uses it).

Instances running a release from before this change cannot read the new format
and keep the sensor and SDK versions built into their release (the check
reports an invalid feed) until they upgrade: the feed is display-only and
nothing else depends on it.

### What an instance shows when the feed is missing

| State | Log (one warning when the state changes) | Console > System |
|---|---|---|
| No Sigstore trusted root loaded | once at start-up | "No release feed key in this build" |
| Feed URL answers 404 | `reason=not_published` | "Release feed not published" |
| Signature or content refused | `reason=invalid` | "Release feed signature invalid" |
| No network / DNS / TLS | `reason=unreachable` | "Release feed unreachable" |
| Feed past its expiry | `reason=expired` | "Release feed expired" |
| OK again | one info line | "OK" and the last success time |

## Key files

- `server/pkg/releasefeed/` — format, verification, comparison
- `server/pkg/contentpkg/sigstore/` — the offline Sigstore verifier and the embedded trusted root (shared with the content catalog)
- `server/internal/app/versioncheck/` — fetcher, schedule, import, console view
- `server/internal/infra/controller/version_check.go` — hourly wake-up
- `server/internal/infra/postgres/version_check_repository.go` — the state row
- `server/internal/infra/http/handler/admin_version_check_handler.go` — console routes
- `server/cmd/release-feed/` — feed tooling
- `.github/workflows/release-feed.yml`, `.github/release-feed/` — publishing
