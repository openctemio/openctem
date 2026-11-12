# Versions manifest

Design: [RFC-037 §12](../rfcs/RFC-037-versioning-and-release-train.md) (one release feed for every component) and
[version check](version-check.md) (the signed instance feed it is built next to).

The documentation site, the website and install scripts need the current releases: the platform
release and its image digests, the newest sensor, SDK, CI runner and Helm chart, which platform each
component needs, and which component releases a platform release accepts. They read them from one
signed file, so a release needs **no commit** in the documentation or the website:

```
https://get.openctem.io/releases/manifest.json
https://get.openctem.io/releases/manifest.json.sigstore.json
```

## Addresses

`get.openctem.io` is the stable public address. It hosts nothing: each path is a redirect to a
GitHub release asset, so publishing a release is the only publishing step and there is no second
copy to keep in sync.

| Path | Redirects to (302) |
|---|---|
| `/releases/manifest.json` | `https://github.com/openctemio/openctem/releases/latest/download/openctem-versions.json` |
| `/releases/manifest.json.sigstore.json` | `.../releases/latest/download/openctem-versions.json.sigstore.json` |
| `/releases/feed.json` | `.../releases/latest/download/openctem-releases.json` (the instance feed) |
| `/releases/vX.Y.Z/<file>` | `.../releases/download/vX.Y.Z/<file>` (that release's own assets: image list, checksums, archives) |
| `/` and `/install.sh` | reserved for the one-script installer when it ships (`.../releases/latest/download/install.sh`) |

The redirects are Cloudflare Single Redirect rules in the `openctem.io` zone (the zone already serves
`openctem.io`); TLS is the zone's certificate, which covers first-level subdomains. A per-release
path serves the assets of that release; the manifest exists only at the latest path, since the
current releases are a property of the day, not of one release.

Until `get.openctem.io` answers, consumers use the GitHub address directly:

```
https://github.com/openctemio/openctem/releases/latest/download/openctem-versions.json
https://github.com/openctemio/openctem/releases/latest/download/openctem-versions.json.sigstore.json
```

Both are the same bytes, so the signature check is the same.

## Who writes it

The Release Feed workflow (`.github/workflows/release-feed.yml`) builds it in the same run as the
instance feed (`openctem-releases.json`), from the same payload, after every release and every six
hours (`server/cmd/release-feed manifest`):

| Field | Source |
|---|---|
| `platform.version`, `published_at`, `notes_url`, `previous` | the newest stable releases of this repository (the feed payload: no draft, no pre-release) |
| `platform.images` | `openctem-images-<tag>.txt` of that release (name, reference, index digest) |
| `platform.accepts` | the `min` values of `versions.yaml` at that tag: the oldest sensor, connector, SDK and CI runner release it supports |
| `components[]` | the newest stable release of each first-party component, with its image digest (the feed payload) |
| `components[].requires_platform`, `requirements` | `.github/release-feed/compat.json`: "releases of this component from X on need platform Y, because ..." |
| `chart` | the newest stable `openctem` chart and its `appVersion` in the Helm repository index |
| `advisories` | `.github/release-feed/advisories.json` (the same list instances read) |

`schema` is `openctem.io/versions/v1`. A reader refuses another schema; renaming or removing a field
is a new schema version, adding one is not.

`compat.json` changes only when a component's contract with the platform changes (a new route, a new
signature requirement), never per release. An entry needs a reason; the release-feed tests refuse an
unknown component or an entry without one.

## Trust

The manifest is signed keyless by the same workflow identity as the instance feed (cosign
`sign-blob`, bundle `openctem-versions.json.sigstore.json`). The publish job verifies it before the
upload, exactly as a consumer does:

```bash
cosign verify-blob --bundle openctem-versions.json.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/openctemio/openctem/\.github/workflows/release-feed\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com openctem-versions.json
```

Threat: a tampered manifest would print an attacker's digest in the install guides. The documentation
build refuses a manifest whose signature does not verify against this identity and keeps the
published site as it was. The digests are also the ones the signed image list names, and every image
is signed itself; the guides tell readers to verify the image, not the manifest.

## Failure modes

- **Image list not published yet.** On release day the Release Feed run can start before
  `docker-publish.yml` has attached the image list. The manifest step then warns, the instance feed is
  published alone, and the next run (at most six hours later) publishes both. The manifest never holds
  the instance feed back.
- **A bad release.** Mark it a pre-release on GitHub (`gh release edit vX.Y.Z --prerelease`) and run
  the Release Feed workflow: neither file lists a pre-release, so both fall back to the release before
  it, and the documentation and the website follow at their next build. A sensor, SDK or CI runner
  release is withdrawn the same way in its own repository.
- **GitHub API limits.** Consumers download two release assets (no API call), so they are not rate
  limited. The workflow itself uses its own token.
- **Offline readers.** The documentation site is static: what it printed at its last build stays.

## Consumers

- Documentation (`openctemio/docs`): the site build downloads and verifies the manifest and writes
  `_data/versions.yml` and `_data/compat.yml` (never committed), so every guide and the compatibility
  table follow the current release. A scheduled check fails when the published site lags the latest
  release by more than a day.
- Website (`openctemio/website`): reads it at build time.
- The Release Feed run asks both to rebuild (`repository_dispatch` `release-published`, needs the
  `DOCS_DISPATCH_TOKEN` secret); both also rebuild on a schedule, so a missing token only delays them.
