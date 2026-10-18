# RFC-105: Version check and usage telemetry

| | |
|---|---|
| Status | Accepted (2026-10-16). Version check: implemented (API, release pipeline); console page in review. Usage ping: designed, deferred (not built) |
| Architecture | [version-check.md](../architecture/version-check.md) |
| Scope | api (signed release feed format, fetcher, offline import, console endpoints), web (console banner and page), release pipeline (feed builder and publishing) |
| Related | RFC-022 (platform console), RFC-037 (versioning and release train), RFC-065 §16 and RFC-066 §5.5 (signed feeds: the shared envelope and key set), RFC-099 (content packages) |

## 1. Summary

A self-hosted instance must learn that a newer release exists, and above all
that the release it runs has a published security fix. It must learn this
without telling anyone anything about itself: OpenCTEM is a security product,
customers run it on sensitive networks, some of them air-gapped.

Decision:

1. **Version check: built, on by default.** The instance downloads one public,
   signed, static file ("the release feed"), verifies it with a public key pinned
   in the binary, and compares it with its own version locally. The request
   carries no instance id, no version, no counts, no cookies. The platform
   console shows "update available" and, when an advisory affects the running
   version, "security release: upgrade". Offline it fails silently and backs
   off; air-gapped installs import the same signed file in the console;
   `VERSION_CHECK_ENABLED=false` turns it off.
2. **Usage ping: not built.** If it is ever built it is off by default, enabled
   only by a console administrator after seeing the exact JSON it would send,
   aggregate counts only (§8).

## 2. What we need

| Need | Why |
|---|---|
| Administrators of self-hosted instances learn about security releases | The instance holds an organization's attack surface and findings. A known, fixed vulnerability left unpatched on it is the most likely way it gets breached. |
| Nothing about the customer leaves the server by default | Customers choose self-hosting to keep data in. A security tool that phones home with identifiers loses trust and, under GDPR, needs a lawful basis for every identifier it sends (an IP address and a stable instance id are personal or pseudonymous data). |
| Works the same air-gapped | No outbound call may be needed for correctness; an offline path must give the same information. |
| The information cannot be forged | A banner that says "security release, download it here" is a phishing vector against administrators of a security product. TLS alone does not cover an intercepting proxy or a compromised download host. |
| Product usage numbers for the vendor | Useful for roadmap decisions, not needed today; the hosted service already has its own metrics. Not a reason to send anything from customer installs by default. |

## 3. Patterns evaluated

Common patterns in self-hosted software, described generically:

| Pattern | How it works | Assessment |
|---|---|---|
| A. Browser-side check | The administrator's browser loads an image or JSON from the vendor with the running version in the URL. | The request leaks the instance's hostname in the `Referer` header and the version in the URL, and a browser on a locked-down admin network often cannot reach the vendor anyway. Rejected. |
| B. Identifying server check | The server posts its id, version and some counts to the vendor and gets "up to date / upgrade / upgrade now" back. | Simple to evaluate centrally, but every instance is identified and counted every day. It is usage telemetry under another name. Rejected. |
| C. Version piggybacked on a usage beacon | The usage beacon's answer carries the latest version. | Turning telemetry off also turns off security notices, which pushes administrators to choose between privacy and safety. Rejected. |
| D. Static file, local comparison | The server downloads a static file listing releases and compares locally. | Sends nothing but the request itself; the file is the same for everyone and can be mirrored or carried in by hand. Usually not signed. **Chosen, with a signature.** |
| E. Default-on usage ping with payload preview | Weekly aggregate usage report, on by default, admin can opt out and see the payload. | Transparent, but default-on still sends identifiers from installs whose operators never looked at the setting. Not acceptable for this product by default (§8). |
| F. Opt-in, local-first telemetry | Counters collected locally; an administrator opts in to upload; the upload schema is public; aggregates only. | The right shape if a usage ping is ever built (§8). |

Privacy and GDPR: pattern D processes no personal data of the customer on our
side. The download host sees the source IP of the request, as for any
download; we do not receive it (the host reports only aggregate download
counts). Documented in the architecture doc and the privacy notes so an
operator can decide.

## 4. Decisions

| # | Decision |
|---|---|
| D1 | The version check is on by default (`VERSION_CHECK_ENABLED`, default `true`). It is a server-side `GET` of one static file with no query string, no cookies, no `Referer`, and a fixed `User-Agent` (`openctem-version-check/1`) that names no version. Comparison happens on the instance. |
| D2 | The file is one DSSE envelope in the shared signed-feed format (`pkg/feedsign`), signed directly by one online Ed25519 key (kind `openctem.io/release-feed/v1`), in the file `openctem-releases.json`. There is no key set and no offline root for the feed: the feed is display-only (D9), so a second tier would add ceremony without protecting anything the first tier does not. The payload type (`application/vnd.openctem.release-feed+json`) is the feed's own (domain separation). The release feed key signs only the feed: the content catalog has its own, separate online key, because a key that signs information must not be able to ship code. |
| D3 | The online public key is pinned in the binary (`releasefeed.PinnedKeys`, hex, at most two entries), not configurable. A configuration override would let anyone with access to the environment make the console say anything; a fork that publishes its own releases rebuilds with its own key. Rotation: a release pins the new key alongside the old one (two entries), the feed switches to the new key, and a later release drops the old one. Until a key is pinned, the check is inert and the console says so. |
| D4 | The feed is published as an asset of the latest GitHub release of `openctemio/openctem`; the default URL is `https://github.com/openctemio/openctem/releases/latest/download/openctem-releases.json`. The release workflow publishes it on every release and a weekly scheduled run re-signs it (so it never expires between releases). `VERSION_CHECK_URL` points an instance at a mirror; the signature makes every host untrusted, so moving the feed to openctem.io later only changes the default. |
| D5 | Anti-rollback and anti-freeze: the feed carries a sequence and an expiry (at most 45 days after issue). An instance refuses a feed whose sequence is below the one it applied, a feed with the applied sequence but other content (it stores the payload digest), and an expired feed. A stored feed that has passed its expiry is shown as out of date with its date, never silently trusted. |
| D6 | Cadence: once a day with up to four hours of random delay; the first check runs 5 to 60 minutes after start-up. After three failed checks in a row (an offline or air-gapped instance) it checks once a week, and logs one line per check, not an error storm. Replicas share one state row; a conditional update elects the replica that fetches. |
| D7 | Fetch limits: the SSRF-guarded client (`pkg/httpsec`), 30 s timeout, at most 256 KiB read, at most 3 redirects. The URL must be HTTPS, a mirror included: the signature carries the trust, HTTPS keeps the request private on the way, and a redirect to plain HTTP is refused. An internal mirror on a private address needs the instance's private-egress allowlist like every other outbound call. |
| D8 | Offline import: a super administrator uploads the same file in the console (route-level step-up, audited). It goes through exactly the same verification, including rollback and expiry. No request names a path or URL. |
| D9 | What the feed may say is bounded so even a stolen online key cannot do much: release versions are `vX.Y.Z`, advisory severities are low/medium/high/critical, texts are short plain text, links must be HTTPS under `github.com/openctemio/`, `openctem.io` or `docs.openctem.io`. The console renders text as text. The instance never downloads or runs anything because of the feed: upgrading stays the operator's action. |
| D10 | Only platform administrators see it, in the platform console: a banner on every console page when an update or a security release applies, and a page with the status, the releases newer than the running one, the advisories that affect it and the offline import. Organization users see nothing. |
| D11 | Development builds (`vX.Y.Z-dev+sha`) are compared as their base release `vX.Y.Z`; release candidates are compared as themselves (the final release is newer). |
| D12 | The hosted service runs the same code; its operators may disable the check. |
| D13 | A usage ping is not built now (§8). |

## 5. Feed format

`openctem-releases.json`:

```json
{
  "schema": "openctem.io/release-bundle/v1",
  "feed":   { "payloadType": "application/vnd.openctem.release-feed+json",   "payload": "…", "signatures": [ … ] }
}
```

The feed payload:

```json
{
  "kind": "openctem.io/release-feed/v1",
  "sequence": 1792000000,
  "issued_at": "2026-10-16T00:00:00Z",
  "expires_at": "2026-11-30T00:00:00Z",
  "releases": [
    { "version": "v0.9.8", "published_at": "2026-10-20T10:00:00Z",
      "notes_url": "https://github.com/openctemio/openctem/releases/tag/v0.9.8" }
  ],
  "advisories": [
    { "id": "OCTEM-2026-0001", "severity": "high", "title": "…",
      "introduced": "v0.9.0", "fixed_in": "v0.9.8", "published_at": "2026-10-20T10:00:00Z",
      "url": "https://github.com/openctemio/openctem/security/advisories/…" }
  ]
}
```

- The sequence is the issue time in Unix seconds, so every re-sign is newer.
- An advisory affects a version `v` when `introduced <= v < fixed_in`
  (`introduced` optional). A release that fixes an advisory is a security
  release.
- Limits: 256 KiB file, 200 releases, 200 advisories, titles of at most 200
  characters, no control characters, unknown fields refused.

The builder (`api/cmd/release-feed`) creates the key and builds
the file from the list of published releases and the advisories file
committed in the repository (`.github/release-feed/advisories.json`, edited
when an advisory is published). The release workflow runs it; it skips with a
warning while the signing key secret is not set, so releases never fail on it.

## 6. Threat model

| Threat | Mitigation |
|---|---|
| Network attacker or TLS-intercepting proxy changes the answer | Ed25519 signature by a key pinned in the binary; anything that does not verify is discarded and the previous state kept. |
| Download host or account compromised | Same: the host is untrusted. Forging needs the online key. |
| Replay of an old feed to hide a newer release (rollback) | Sequence never below the applied one. |
| Withholding updates (freeze) | Feeds expire within 45 days; the console shows the date of the information and flags it as out of date. |
| Online signing key stolen (CI secret) | The feed is display-only (D9): bounded fields, allowlisted links, no download or execution. Recovery: ship a release that pins a new key and drops the stolen one, then rotate the secret; until instances upgrade they still accept the stolen key, which the display-only limits make tolerable. The online key lives in a protected GitHub environment. See [signing keys](../architecture/signing-keys.md). |
| Phishing banner ("security release, download here") | Links restricted to our hosts, verified signature, React text rendering, no HTML in the feed. |
| Oversized or malicious response | 256 KiB read cap, strict JSON decoding, bounded lists and texts, timeouts, redirect cap. |
| SSRF through the URL setting | Only the operator's environment sets it; the guarded client still refuses internal ranges unless the operator allowlisted them. No request can name a URL. |
| Privacy leak | No identifiers, no version, no counts, no cookies; one anonymous download a day. The download host sees the source IP; disclosed in the documentation; `VERSION_CHECK_ENABLED=false` stops it. |
| Air-gapped noise | Fails silently with backoff; offline import gives the same result. |
| Authorization | Read: any platform administrator. Import: super administrator, route-level step-up, high-severity admin audit row. Not reachable from the tenant API; the data is instance-level and holds no tenant data, so tenant isolation is unaffected. |
| Abuse of the vendor endpoint | Static public file on a CDN; nothing to enumerate, no per-instance state on our side. |

## 7. What is not in this RFC

- Automatic upgrades or downloads: never from the feed.
- Notifications by email or to organization users: the console banner only;
  can be added later on the same status.
- Sensor and SDK update notices: sensors already report their versions to the
  platform (RFC-037), which compares them with its manifest. The feed also
  carries the newest release of each first-party sensor product and of the
  SDK (`components`, RFC-037 §12), so those notices and the install snippets
  follow a sensor or SDK release without a platform release. A component
  carries only a version, a date, a link and an image digest; the image
  repository comes from the built-in catalog, and a learned version can only
  raise the built-in one.

## 8. Usage ping (deferred design)

Not built. Recorded so the decision is not reopened without these rules:

1. **Off by default** in every self-hosted edition. Only a super
   administrator turns it on, in the console, with a reason, audited. No
   environment variable turns it on silently; an environment variable can
   force it off.
2. **Preview first:** the console shows the exact JSON of the next report
   before the switch can be turned on, and keeps the last sent report
   viewable.
3. **Aggregates only:** counts and booleans (number of organizations, users,
   assets, findings by severity band, enabled modules, sensor count,
   edition, version). Never domains, IPs, asset names, finding titles or
   details, user names, emails, organization names or free text.
4. **No stable identifier:** a random report id rotated on every report; no
   hostname; counts bucketed (for example 1–10, 11–100) so a report cannot
   fingerprint a customer.
5. **Separate from the version check:** turning usage reporting off never
   turns off security notices, and the version check never carries usage.
6. **Air-gapped:** an export of the same JSON for the administrator to send by
   hand, never required.
7. **Public schema:** the report schema is versioned in the repository; a
   field is added only through an RFC change.
8. **Data handling on our side:** documented retention, no join with other
   data, deletion on request; the privacy notice and the data processing
   terms name it before it ships.
9. **Enterprise licence:** if a future signed licence needs usage figures,
   they come from the licence check's own minimal data, stated in the licence
   terms, not from this ping.

## 9. Owner actions

- Run `scripts/signing/init-keys.sh` on your own machine (see
  [signing keys](../architecture/signing-keys.md)); it creates the release feed key,
  a separate catalog online key and the catalog root.
- Pin the printed online public key in `api/pkg/releasefeed` (`PinnedKeys`)
  in a reviewed pull request.
- Store the release feed key seed as the `RELEASE_FEED_SIGNING_KEY` secret of a
  `release-feed` GitHub environment limited to `main` and protected `v*` tags
  (the publish job also refuses any other ref). The catalog online key is a
  different key in a different environment (`content-catalog`); the release feed
  key never signs catalog documents.
- Once a year: `scripts/signing/rotate-keyset.sh` (the content catalog key set; the release feed has none).
