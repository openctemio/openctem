# RFC-031 — Managed sensor updates: scanner content now, signed images next

> Status: **Part A implemented** in the API (tenant content policy:
> `sensor_content_policies`, sensor content routes); **Part B Proposed**.
> Scope: sensor (`openctemio/sensor`) + sdk-go + api + ui.
> Builds on: [RFC-023](RFC-023-scan-zones-and-scanners.md) (sensors, the
> doorbell's reserved `update` action), [RFC-026](RFC-026-sensor-results-ingest.md)
> (v2 results, `ingest_reports.header`), [RFC-029](RFC-029-sensor-protocol-v2-and-sdk-stability.md)
> (protocol v2, sensor-reported tools §4.3.1, evolution rules §4.11) and
> #679 (fleet health: state ladder, health reasons, release channel).
> Operator view: [architecture/sensors.md](../architecture/sensors.md).
>
> Question (2026-10-02): **"Can the sensor hot-update third-party
> tools like trivy?"**

## 1. Answer in short

A scanner is two things that age at very different speeds:

| | Changes | Today (verified 2026-10-02) | After this RFC |
|---|---|---|---|
| **Binary** (`trivy`, `nuclei`, `semgrep`, `betterleaks`) | monthly | pinned in the Dockerfiles (trivy 0.69.3, nuclei 3.4.1, semgrep 1.178.0, betterleaks 1.9.0), each checked by sha256 or Sigstore at image build | still only through a new sensor image or release archive, **signed** by the sensor's release workflow and installed by digest after verification (Part B) |
| **Content** (trivy vulnerability DB, nuclei templates, semgrep rules) | hours to days | uncontrolled: trivy downloads its DB inside every scan; nuclei templates are baked at image build and nuclei auto-updates them at scan start; semgrep fetches `--config auto` from the registry on every scan | **managed by the sensor** (Part A): refreshed on a schedule and on demand, verified, swapped atomically with the previous version kept, used explicitly by every scan, reported to the platform, governed by a tenant policy |

So: **yes for content, hot and controlled; no for binaries in place.** A
binary changes only by installing a new signed release, which Part B makes a
one-click, staged, verified and reversible operation. Hot-patching a tool
binary inside a running sensor would break the image's provenance (what was
scanned with what can no longer be proven), cannot be verified against our
release identity, and buys little: tool releases are monthly, content is
what goes stale in hours.

## 2. Decisions

| # | Decision |
|---|---|
| D1 | Content and binaries are separate update paths. Content: sensor-managed, continuous. Binaries: whole signed sensor releases only. |
| D2 | The sensor owns content sources (registries, mirrors, local directories) as **host configuration**. The platform's policy can set freshness (max age), pins (a digest or tag) and semgrep rulesets, but never a URL. A compromised platform cannot point a fleet at other content. |
| D3 | Every content kind has an integrity check before it is used (§4.3). A failed fetch or check never replaces the current version; the sensor keeps scanning with what it has and reports the error. |
| D4 | Swaps are atomic (staging directory, verify, rename, symlink flip) and never touch a running scan: a scan resolves its content version when it starts and keeps it. The previous version is kept for rollback. |
| D5 | Scans use the managed content explicitly (`trivy --cache-dir <version> --skip-db-update`, `nuclei -t <version> -disable-update-check -disable-unsigned-templates`, `semgrep --config <version>` when rules are managed), so tools stop fetching on their own. |
| D6 | Content versions travel in the existing reported-capabilities structure (`tools[].content`, RFC-029 §4.3.1): additive, ignored by a platform that does not know it. |
| D7 | On-demand refresh is a command (`refresh_content`), not a doorbell action: it is pinned to one sensor, claimed once, carries the policy, and returns the new versions as its result. Only sensors that report managed content are sent one. |
| D8 | Stale or failing content is a fleet-health reason (`content_stale`, `content_refresh_failed`): the sensor shows `degraded`, with the message ("trivy DB is 3d old (limit 2d)…"). |
| D9 | Each scan result records the content it used (`tool.properties.content` in the CTIS report; CTIS 1.3 `Properties` is open), so a finding can be traced to the DB or template release that produced it. |
| D10 | semgrep rules are managed only when the tenant (or the sensor host) names rulesets. Switching from `--config auto` to fixed rulesets changes what scans find, so it is opt-in; unmanaged rules are reported as such (`managed: false`). |
| D11 | Sensor images and release checksums are signed with cosign keyless signing by the sensor's release workflows (sensor#82). The trust root for Part B is the certificate identity `https://github.com/openctemio/sensor/.github/workflows/{docker-publish,release}.yml@refs/tags/v*` issued by `https://token.actions.githubusercontent.com`. |
| D12 | Part B never lets the platform choose *what* runs, only *which signed release* and *when*: a sensor installs an update only if the signature matches D11's identity, the version is not older than what runs (no downgrade without a local override), and the image repository is on the sensor's local allow-list. |

## 3. Current state (verified 2026-10-02)

- `Dockerfile*` install the tool binaries at fixed versions with sha256
  checks (nuclei, trivy, betterleaks) or a Sigstore-verified wheel (semgrep).
- **trivy**: no image except `trivy-ci` ships a DB. Every `trivy fs` run
  checks the DB's `NextUpdate` and downloads ~1.5 GB from
  `mirror.gcr.io/aquasec/trivy-db:2` (fallback `ghcr.io/aquasecurity/trivy-db:2`)
  into `$TRIVY_CACHE_DIR` when it is due, inside the scan, with no record of
  which DB the scan used. Two concurrent scans race for the same cache.
- **nuclei**: `Dockerfile.nuclei` bakes `nuclei-templates` at build time
  (stale until the next image). At scan start nuclei checks for newer
  templates and installs them into `$HOME/nuclei-templates` unless
  `-disable-update-check` is given; the sdk-go scanner never passed it. The
  templates are signed by their publisher, but unsigned or tampered templates
  were still executed (only `code` templates are refused by default).
- **semgrep**: `internal/executor/vulnscan.go` and the sdk-go scanner run
  `--config auto`: every scan fetches rules from the registry, chosen by the
  registry, with no version.
- The sensor images were not signed; `checksums.txt` of a release was not
  signed.

## 4. Part A — scanner content (Phase 1, in implementation)

### 4.1 Content kinds

| Name | Tool | Source (default; host-configurable) | Version | Digest | Size |
|---|---|---|---|---|---|
| `trivy-db` | trivy | OCI `mirror.gcr.io/aquasec/trivy-db:2`, then `ghcr.io/aquasecurity/trivy-db:2` | DB build time (`UpdatedAt`) | OCI manifest digest | ~1.5 GB, ~10 s |
| `trivy-java-db` | trivy | OCI `trivy-java-db:1` (opt-in) | build time | manifest digest | large; opt-in |
| `nuclei-templates` | nuclei | GitHub release archive of `projectdiscovery/nuclei-templates` + its `_checksums.txt` asset | release tag (`v10.4.9`) | archive sha256 | ~10 MB archive, ~11k templates |
| `semgrep-rules` | semgrep | `https://semgrep.dev/c/<ruleset>` per named ruleset, or a local rules path | `sha256:` prefix of the bundle | bundle sha256 | ~2.4 MB for `p/default` |

Air-gapped installs point each source at a local mirror or directory (sensor
README, "Scanner content updates"): an OCI registry holding the trivy DB
(`oras copy` or `trivy image --download-db-only` + push), an internal web
server or a mounted directory holding the template archive and its checksums
file, a rules file for semgrep.

### 4.2 Lifecycle on the sensor

```
schedule (interval ± jitter) ─┐
refresh_content command ──────┼─► single-flight per content
content older than max age ───┘        │
                                       ▼
          resolve (digest / tag, honouring the policy pin)
                                       │  same as current and not forced → done
                                       ▼
          fetch into <root>/<name>/.staging-*   (bounded size, timeout)
                                       ▼
          verify (§4.3)  ── fail ──► delete staging, keep current, record error
                                       ▼ ok
          rename to versions/<id>, write meta.json, flip `current` symlink
                                       ▼
          garbage-collect: keep current + previous + any version a scan holds
```

A scan acquires the current version when it starts (a reference count) and
releases it when it ends; garbage collection skips held versions, so a
multi-hour scan keeps a consistent DB even if two refreshes happen meanwhile.
Content baked into an image (nuclei templates, the `trivy-ci` DB) is imported
once as the first version (`source: "image"`), so a fresh sensor scans
immediately and offline. `SENSOR_CONTENT=off` restores the old behaviour.

### 4.3 Integrity

| Content | Checks before a version is used |
|---|---|
| trivy DB | the sensor resolves the tag to a manifest digest (anonymous OCI token flow, or registry credentials from the host) and downloads **that digest** (`--db-repository <repo>@sha256:…`; trivy verifies every blob against it); `trivy version --cache-dir` must read schema 2 and a build time; **anti-rollback**: a DB older than the current one is refused unless the policy pins exactly that digest |
| nuclei templates | archive sha256 equals the release's published checksums file (or the pinned sha256 for a mirror); safe extraction (no absolute paths, `..`, links leaving the tree, size cap); at least N templates and `nuclei -tl` loads them. At scan time `-disable-unsigned-templates` skips any template whose publisher signature is missing or wrong (verified: a tampered template is skipped with "Skipping 1 unsigned template"); platform-provided custom templates are exempt (not publisher-signed) |
| semgrep rules | TLS to the registry (or a local file the host trusts); YAML with a non-empty `rules` list where every rule has an id; `semgrep scan --config <bundle>` on an empty directory exits cleanly (measured: `semgrep --validate` takes ~2 minutes, so it is not used) |

### 4.4 Policy (platform → sensor)

Tenant policy, stored by the api (`sensor_content_policies`), edited under
**Settings → Scanning → Scanner content** by administrators, defaults shown
when unset:

```json
{ "refresh_interval_hours": 6,
  "content": {
    "trivy-db":         { "max_age_hours": 48 },
    "trivy-java-db":    { "max_age_hours": 168 },
    "nuclei-templates": { "max_age_hours": 336, "version": "v10.4.9" },
    "semgrep-rules":    { "max_age_hours": 168, "rulesets": ["p/default"] } } }
```

`version` pins (digest for a DB, tag for templates); `rulesets` turns semgrep
rule management on (D10). The policy reaches sensors on `refresh_content`
commands (saving with "apply now" sends one to every eligible sensor) and the
sensor persists it for its own schedule. There is no source member (D2).

### 4.5 Protocol

Additive inside protocol v2 (RFC-029 §4.11), types in sdk-go `pkg/core`:

- Heartbeat: `tools[].content[]` = `{name, version, updated_at, fetched_at,
  source, digest, managed, error}`.
- Command `refresh_content`, payload `{content?: [names], force?: bool,
  policy?: {...}}` decoded by `core.ParseRefreshContentRequest` (bounded,
  no flag-shaped values). Pinned to the sensor, expires after 24 h, one
  pending per sensor. Result metadata: the sensor's content after the
  refresh, the names refreshed and the failures. An old sensor never sees the
  type: the api sends it only to sensors that report managed content (the
  SDK poller would otherwise leave an unknown type pending).

### 4.6 Platform

- Sensor read model: `content[]` per sensor with `age_seconds`, `stale`,
  `max_age_hours`, `pinned_version`, `pin_mismatch`, and
  `content_refresh_supported`.
- Health reasons `content_stale` and `content_refresh_failed` (warning).
- `POST /api/v1/sensors/{id}/content/refresh`, `POST /api/v1/sensors/content/refresh`
  (fleet), `GET|PUT /api/v1/sensors/content-policy`; writes need
  `sensors:write` (owners and administrators) and are audited.
- Provenance: the CTIS `tool.properties.content` of a v2 report is kept in
  `ingest_reports.header` (RFC-026), linked to findings by `scan_id`; no
  finding columns are added.

### 4.7 Failure modes

| Failure | Behaviour |
|---|---|
| upstream down, mirror down | keep current, retry on the next check with backoff; `content_refresh_failed`, then `content_stale` once past max age |
| verification fails (bad checksum, corrupt DB, older DB) | staging deleted, current kept, error reported; nothing is ever half-installed |
| disk full during fetch | fetch fails, staging deleted; current untouched (size the volume for two DB versions: ~3–4 GB with the Java DB off) |
| sensor restarts mid-swap | a staging directory is deleted at start; `current` is a single symlink, so it points to the old or the new version, never neither |
| no managed version yet (first start, offline, no baked content) | scans run as before (tool-managed), the content is reported missing |
| policy pins a version the source does not have | refresh fails with the pin in the error; current kept |

## 5. Part B — managed sensor updates (Phase 2, proposed)

### 5.1 Goals

An administrator sees which sensors run an old release (api#679's
`version_status`: `update_available`, `unsupported`) and clicks **Update**
(one sensor, a zone, or the fleet). The sensors move to the target release
**by digest**, verified against our release identity, self-test, and roll back
by themselves if the new release does not come up healthy. Every step is
audited. The platform cannot make a sensor run anything that our release
workflow did not build and sign.

### 5.2 Release side (what the sensor repository publishes)

1. **Signed images** (implemented in sensor#82): `docker-publish.yml` signs
   each image index and platform manifest by digest (`cosign sign
   --recursive`, keyless, GitHub OIDC), verifies it in the same job, and signs
   the Docker Hub copies.
2. **Signed checksums** (sensor#82): `checksums.txt` of a release carries a
   Sigstore bundle `checksums.txt.sigstore.json` from `release.yml`.
3. **Release manifest** (next): `sensor-release.json` attached to each
   release and signed the same way:
   ```json
   { "name": "openctemio-sensor", "version": "v0.6.0", "published_at": "…",
     "min_platform": "v0.10.0",
     "images":    [{ "variant": "default", "repository": "ghcr.io/openctemio/sensor", "digest": "sha256:…" }],
     "artifacts": [{ "os": "linux", "arch": "amd64", "url": "…/openctemio-sensor_0.6.0_linux_amd64.tar.gz",
                     "sha256": "…", "size": 41234567 }] }
   ```
   The api learns releases from it (an hourly fetch from the sensor
   repository's releases, or a file an air-gapped operator imports), so the
   platform knows each release's digests without trusting a registry tag.

### 5.3 Platform side

- **Release channel** (exists, api#679): `SENSOR_LATEST_VERSION`,
  `SENSOR_MIN_VERSION`; extended with the known releases from 5.2.3.
- **Update campaign**: `{target_version, selector (sensor ids | zone | labels |
  all), waves: [5%, 25%, 100%], wait_between_waves, max_failure_ratio}`.
  The api assigns each selected sensor a `desired_release` (version + digest
  for its variant and architecture) wave by wave; a wave starts only when the
  previous one is healthy for `wait_between_waves`, and the campaign pauses
  itself when failures exceed `max_failure_ratio`. Canary first.
- **Signal**: the heartbeat answer's reserved `update` action (RFC-029 §4.3)
  rings for a sensor with a desired release; the sensor reads it from a new
  v2 feature `GET /api/v2/sensor/update` → `{version, image: {repository,
  digest}, artifact: {url, sha256, bundle_url}, campaign_id}`.
- **Audit**: campaign created/paused/resumed/cancelled (who), each sensor's
  transition (`assigned → downloading → verifying → self-test → switching →
  confirmed | rolled_back | failed`, with reason) reported by the sensor on
  its heartbeat (`update: {state, version, digest, at, error}`).
- UI: Update button per sensor and on the fleet, campaign progress, the
  reasons of failures, a pause/cancel control.

### 5.4 Sensor side, by install type

The check is the same everywhere (D12): **signature identity**, **monotonic
version** (≥ current, ≥ the local floor; downgrades only with
`SENSOR_UPDATE_ALLOW_DOWNGRADE=true` on the host), **repository on the local
allow-list** (`SENSOR_UPDATE_REPOSITORIES`, default
`ghcr.io/openctemio/sensor,docker.io/openctemio/sensor`), **min_platform**
satisfied. Updates are opt-in per host (`SENSOR_UPDATE=managed`); without it
the sensor only reports that an update is available.

| Install | Who replaces the sensor | Flow |
|---|---|---|
| **Kubernetes / Helm** | the sensor patches its own Deployment's image to `repository@digest` (opt-in RBAC: `patch` on its own Deployment only); the cluster's admission policy (Sigstore policy-controller or Kyverno `verifyImages`, chart values provided) re-verifies the signature | verify → patch → Kubernetes rolling update (new pod must pass readiness = self-test + first heartbeat) → `progressDeadlineSeconds` exceeded ⇒ the old pod keeps running, the sensor patches back and reports `rolled_back` |
| **Docker / Compose** | an opt-in companion `openctemio-sensor-updater` container, the only one with the Docker socket, no inbound ports, talks only to the registry and the local sensor | verify → `docker pull repo@digest` → run the new image once with `-self-test` → recreate the sensor container with the same config and the new digest → wait for its first healthy heartbeat (default 5 min) ⇒ else recreate with the previous digest |
| **Binary / systemd** | the sensor itself | download the signed manifest from the release base URL (local mirror configurable), verify the bundle (sigstore-go, trusted root from TUF; offline: a bundled trusted root + the bundle's transparency-log proof), download the archive, check sha256, run `new -self-test`, rename into place keeping `openctemio-sensor.previous`, exit for systemd to restart; an unconfirmed start (no healthy heartbeat within the window) restores `.previous` on the next start (A/B "confirm" marker) |

**Self-test** (`openctemio-sensor -self-test`, new): every bundled tool runs
`--version`; a fixture scan per tool (trivy on a lockfile with a known CVE
against the managed DB, semgrep with an inline rule, betterleaks on a fake
secret, nuclei `-tl` on the managed templates); the content directory is
readable; prints JSON, exits non-zero on any failure.

### 5.5 Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Upstream tool release compromised (malicious trivy binary) | binaries pinned by version + sha256/Sigstore in the Dockerfiles; image smoke test; a bump is a reviewed PR | a malicious upstream release we choose to adopt; reviewed bumps, no auto-bumps of binaries |
| Upstream content compromised (poisoned DB, malicious template) | trivy DB by digest from the publisher's registry; templates: published checksum + publisher signatures enforced at scan time; semgrep rules can't execute code | a publisher-signed malicious template; same as using nuclei at all |
| Mirror / registry / network attacker | digests, checksums, TLS; a mirror can only withhold content, which shows up as `content_stale` | stale content until noticed (bounded by max age) |
| **Platform compromise** (attacker controls the api) | cannot set content sources (D2); cannot ship binaries: sensors install only images/archives signed by our release workflow identity (D11/D12), at a version not older than the running one; update is opt-in per host; the K8s path is re-verified by admission control | the attacker can trigger refreshes (rate-limited, one pending per sensor), pin an **older** content version (refused by anti-rollback unless pinned explicitly — follow-up: a host-side "oldest acceptable content" floor), or upgrade sensors to a real newer signed release early |
| Downgrade to a vulnerable signed release | monotonic versions + local floor; downgrade needs a host override | — |
| GitHub repository / workflow compromise | tag protection, required reviews, release environment approval; the identity pins the workflow file and `refs/tags/v*`; Rekor monitoring for unexpected signatures | an attacker with write access to the release workflow can sign; this is the root of trust |
| Bad release bricks the fleet | waves with canary, auto-pause on failure ratio, self-test before switch, auto-rollback on missing heartbeat | a bug that passes self-test and heartbeats but scans wrongly; mitigated by the canary wait |
| Updater container abuse (Docker socket) | separate opt-in container, no ports, only verifies-then-pulls by digest from allow-listed repositories | the socket is root-equivalent on that host; Kubernetes or binary installs avoid it |

## 6. Implementation plan

**Phase 1 (this round)**

| Repo | PR | What |
|---|---|---|
| sdk-go | #91 | `ToolInfo.Content`, `ContentInfo`, `refresh_content` + `ContentPolicy`, nuclei `-disable-update-check` / `-disable-unsigned-templates`, validation `TemplatesDir` |
| sensor | (content manager PR) | `internal/content`: sources, verify, atomic swap, policy, schedule; scan wrappers; `refresh_content` executor; heartbeat reporting; `tool.properties.content` on results; README air-gapped recipes |
| sensor | #82 | cosign keyless signing of images and release checksums |
| api | (sensor content PR) | content on the sensor read model, staleness health reasons, tenant policy, refresh endpoints, migration |
| ui | (sensor content PR) | drawer + list freshness, Refresh content (sensor and fleet, admin), Settings → Scanning → Scanner content |

Merge order: sdk-go #91 → tag → sensor content PR (bump to the tag) → api →
ui; sensor #82 any time before the next sensor release.

**Phase 2 (after this RFC is accepted)**: P2.1 release manifest + signature;
P2.2 `-self-test`; P2.3 api releases + campaigns + `GET /api/v2/sensor/update`
+ the `update` doorbell action + heartbeat `update` state; P2.4 Kubernetes
path + chart values (RBAC, admission policy); P2.5 Docker updater companion;
P2.6 binary self-update; P2.7 UI.

## 7. Alternatives considered

- **Replace tool binaries in place** (download a new trivy into the running
  container): rejected (D1). The image stops matching its signature and SBOM,
  scan provenance is lost, and the same verification would have to be rebuilt
  per tool.
- **Let each tool update itself** (today's behaviour): uncontrolled timing,
  no versions on results, no air-gapped story, concurrent-scan races.
- **Plain tag polling**: follows tags, not digests, and verifies
  no signatures.
- **The platform as the content mirror** (sensors pull content from the api):
  attractive for air-gapped tenants, but it makes the platform a content
  source, which D2 forbids unless the content carries the publisher's own
  verification end to end (trivy DB digests from the publisher, template
  checksums + signatures). Possible later as a source a host opts into.

## 8. Open questions

1. Default max ages: trivy publishes a DB every 6 h; 48 h warns early enough
   without noise on a sensor that was off over a weekend? (proposed: 48 h).
2. Should the platform re-send the policy automatically when a sensor reports
   a pinned content version that differs from the policy (`pin_mismatch`), or
   only on "apply now"? (proposed: show it; re-send on the next fleet refresh).
3. A host-side floor for content pins (`SENSOR_CONTENT_MIN_DB_AGE`-style) to
   close the "compromised platform pins an old DB" gap entirely.
4. Phase 2: should sensors with `SENSOR_UPDATE` unset still accept *security*
   releases flagged in the manifest? (proposed: no; show them prominently).
