# RFC-061: Content packs — templates, rules, wordlists and signatures as a contract

| | |
|---|---|
| Status | Proposed (owner 2026-10-08: "a developer writes a tool and wants to point it at templates or rules other than the default: default + custom, custom only, or another source; it must be flexible and there must be a contract the platform understands". And: "should the tool check for updates before running, or should the platform push them? Think through every use case") |
| Authors | Platform team |
| Related | RFC-033 (manifest, `content[]`), RFC-038 §6.12 (signed custom templates), RFC-040 (mutual distrust), RFC-055 (tool contract), RFC-059 (transport v3 control stream), RFC-060 (overrides, confinement) |
| Code (today) | api `pkg/domain/sensor/content.go`, `content_policy.go`, `pkg/domain/scannertemplate`; sdk-go `core/template_signing.go`, `core/command_poller.go` (custom templates written to `$TMPDIR`); sensor `internal/content` (nuclei templates, trivy DB, semgrep rules fetched by the sensor) |

## 1. Summary

Content is the data a tool runs:
- nuclei templates;
- semgrep rules;
- trivy databases;
- wordlists;
- signatures.

Content is code: a template decides what is sent to a target.

Today it reaches a task three ways:
- the sensor fetches upstream releases itself (`sensor/internal/content`);
- custom templates arrive in the job, signed per tenant and written to
  `$TMPDIR` (RFC-038 §6.12);
- the tool's own updater fetches what it wants.

This RFC replaces all three with one contract.

1. **Slots.** A tool declares in `tool.yaml` the content it reads, slot by
   slot (`content:`). The SDK hands it resolved, read-only paths. A tool
   never downloads content.
2. **Packs.** Content is an immutable, content-addressed **pack** (digest),
   linted, classified and signed by the platform.
   - Sources: platform-managed upstream releases, tenant uploads, Git refs,
     OCI artifacts, HTTPS or S3 URLs.
   - The **platform** fetches every source, never the sensor (except
     operator-configured mirrors, §4.6).
3. **Composition per use.** A workflow step, scan policy or capability
   profile chooses `default_only`, `custom_only` or `merge`, plus selectors
   and a version pin or channel.
4. **Desired state + pin at dispatch, never "check latest at run time".**
   - The platform computes each sensor's desired pack set and pushes changes.
   - The sensor prefetches in the background.
   - Each run pins exact digests when it starts.
   - A task checks its local cache by digest only.

## 2. Problem (verified 2026-10-08)

| # | Finding | Evidence |
|---|---|---|
| C1 | No contract: which content a tool reads is code inside the wrapper; a third-party tool cannot declare one | sensor `internal/content/scanners.go` (per-tool Go) |
| C2 | Sensors fetch public content from the internet themselves; each sensor decides when; two sensors in one run can use different template releases | `internal/content/manager.go` refresh interval |
| C3 | Custom templates are written to the sensor's `$TMPDIR`, readable by every concurrent task (residual of sdk-go#208) | sdk-go `core/command_poller.go:1598` |
| C4 | Public packs are tracked by version and digest but not signature-verified end to end; a tool's own updater can fetch outside any policy | api `content_policy.go`; tool flags |
| C5 | No "custom only" or "merge" composition, no selectors outside nuclei tags, no pin per run, no reproducible retest content | RFC-038 §6.12 runs custom templates in their own run |

## 3. Design

### 3.1 Slots (`tool.yaml`, additive)

```yaml
content:
  - slot: templates
    kind: nuclei-templates            # nuclei-templates | semgrep-rules | vuln-db | wordlist | signatures | <vendor>/<kind>
    format: dir                       # dir | file | archive
    default: bundled                  # bundled (a platform pack of this kind) | none
    modes: [default, custom, merge]   # compositions the tool supports
    selectors: [tags, ids, severities, paths]
    mount: {flag: "-t"}               # or {env: NUCLEI_TEMPLATES} or {path: content/templates}
    max_size: 512MiB
    merge_key: id                     # how "custom wins on the same id" is decided
```

- The descriptor validator refuses unknown kinds without a `<vendor>/`
  prefix, sizes above the sensor's cap, and modes the kind cannot support.
- **Go:** `ctx.Content("templates")` returns `{Paths []string, Digest,
  Selectors}`. The paths are read-only bind mounts in the task (RFC-060
  mount namespace; until then, read-only Landlock grants).
- **Adapter protocol:** `run.task.content[]` with `{slot, paths, digests,
  selectors}`.
- **Exec:** `{{content.templates}}` / `{{content.templates.selectors.tags|,}}`
  placeholders, or the declared flag or env.
- **Updaters are disabled.**
  - The toolhost refuses arguments that turn a tool's self-update on (the
    `core.DangerousToolFlags` list grows per kind).
  - The tool's environment disables updaters (for example nuclei's
    `-disable-update-check`, set by the wrapper).
  - Under RFC-060, the forwarder refuses the vendors' update endpoints
    unless they are the tool's declared vendor hosts for that slot (none
    for content kinds).

### 3.2 Packs

A pack is:
`{id, tenant_id | platform, kind, source, version, digest (sha256 of the canonical archive), size, file count, lint report, tier, signature}`.

- **Ingest (platform), for every source:**
  1. fetch, with httpsec, bounded size and count;
  2. unpack safely: no symlinks, no hard links, no `..`, no absolute paths,
     no device files, file count and depth caps;
  3. canonicalise into a tar of sorted entries, giving the digest;
  4. lint per kind;
  5. classify the tier;
  6. scan for secrets;
  7. sign: DSSE, Ed25519;
     - platform packs with the platform content key;
     - tenant packs with the tenant's key (RFC-038 §6.12 keys, extended);
  8. store immutably;
  9. audit.
- **Sources:**

  | Source | Pinning | Who |
  |---|---|---|
  | Platform-managed upstream (nuclei-templates, semgrep registry rulesets, trivy DB) | release tag + digest; channels `stable` and `canary` | platform operator |
  | Tenant upload | digest | tenant admin (`content:packs:write`, step-up) |
  | Git repository | commit SHA (a branch is resolved to a commit at sync) | tenant admin; credentials via the integration store |
  | OCI artifact | manifest digest | tenant admin |
  | HTTPS / S3 URL | content digest | tenant admin; httpsec SSRF guard; no private ranges unless the source is marked internal by the platform operator |
- **Lint and tier classification (content is code):**
  - nuclei:
    - `code`, `javascript`, `headless` and `file` protocols, self-contained,
      interactsh and DoS-like flows (high request counts, `race`), and
      intrusive methods with bodies → tier T2 or refused per tenant policy;
    - network and DNS protocols → at least T1;
  - semgrep: rules are passive (T0), but `--config` URLs inside rules are
    refused;
  - wordlists: size and line caps.

  A pack's tier can never exceed the step's tier ceiling, the job is refused
  before dispatch, and T2 content needs the same approval as a T2 profile.

### 3.3 Composition per use

A step, scan policy or capability profile carries:

```yaml
content:
  templates:
    mode: merge                 # default_only | custom_only | merge
    packs: [org-custom]         # tenant packs (by name; resolved to digests at run start)
    channel: stable             # stable | canary | pinned
    pin: sha256:…               # with channel pinned (compliance freeze); expiry reminder
    include: {tags: [cve, exposure], severities: [high, critical]}
    exclude: {ids: [CVE-2021-12345]}
```

- `merge` means default + custom; custom wins on the same `merge_key`.
- Selectors are applied by the SDK, which builds the task's view (a
  filtered directory or an argument list), not by the tool.
- The resolved set is shown in the step inspector, for example
  "Templates: Default (stable v10.4.9) + Org custom (tags: cve, exposure) ·
  pinned".

### 3.4 Delivery: desired state, prefetch, pin at dispatch

1. **Desired state (platform).** Per sensor, the platform computes:
   (slots its tools declare) × (channels and pins of the tenants it serves)
   ∩ (packs a sensor of that tenancy may hold). The result is a set of
   digests.
2. **Push.**
   - v3: on change, the control stream (RFC-059 `Subscribe`) carries
     `content_changed`.
   - v2: the heartbeat answer carries the desired-set digest; a mismatch
     triggers `GET /content/desired`.
3. **Prefetch.** The sensor downloads missing packs in the background over
   the authenticated channel (resumable, content-addressed chunks).
   - It respects the operator's sync window and bandwidth cap.
   - It verifies signature and digest before storing.
   - It reports cached digests in the RFC-033 manifest (`content[]`, by
     digest).
4. **Pin at dispatch.** When a run starts, the platform resolves the
   composition to exact digests and writes them into the run, like the
   workflow version.
   - Every task of the run carries them, signed with the job (RFC-040), so a
     long run is consistent even if a new release lands mid-run.
   - A retest carries the finding's original digests.
5. **At claim and run.** The sensor checks its cache **by digest**, with no
   network "is there a newer one?" check.
   - Placement prefers sensors that already hold the digests.
   - If a pack is missing, the sensor fetches it on claim with a timeout.
     If that fails, the task fails fast with `content_unavailable` and is
     requeued elsewhere.
   - Integrity is re-verified when the pack is mounted.
6. **Garbage collection.** LRU within the sensor's content budget. It never
   evicts a digest pinned by an active run, a schedule, or an open retest
   that the platform lists in the desired state.

### 3.5 CI runs (openctemio/ci images) and freshness

A CI image is built once and run for weeks, so the content baked into it ages.
The image carries code; the content comes at run time.

1. **Fetch at job start, pinned.** The CI entrypoint resolves the tenant's
   channel (stable, canary or pinned) for its tool's slots and fetches the
   pack digests. Two routes:
   - with a platform: through the platform, using the job's OIDC token
     exchanged for a content-read token of that tenant (RFC-051 exchange);
   - standalone or community use without a platform: from public signed OCI
     artifacts `ghcr.io/openctemio/content/<kind>:<channel>`, cosign-verified
     against the release workflow identity.

   Results record the exact digests used.
2. **Cache by digest.** GitHub Actions cache, the GitLab cache or a generic
   directory is keyed by digest, so an unchanged pack is never downloaded
   twice. The platform or mirror route avoids public registry rate limits.
3. **Vulnerability databases are content.** A `vuln-db` kind (the SCA
   scanner's advisory database, updated several times a day) has its own
   freshness rules and is mirrored and cached the same way.
4. **Freshness policy:** `content: required | preferred | baked`.

   | Mode | Fetch fails | Baked content too old |
   |---|---|---|
   | `preferred` (default) | Run on the baked content, WARN in the job log, mark results `content_stale` with its age | > 7 days: warn; > 30 days: fail |
   | `required` | Fail the job | Fail |
   | `baked` | Not fetched | Warn only |

   Freshness is shown in the PR comment and job summary.
5. **Catch-up on the platform, so nothing is missed between commits.**
   - CI uploads the SBOM and the scanned-file inventory. The platform keeps
     matching stored SBOMs against new advisories, so a new CVE becomes a
     finding on the repository without a new CI run.
   - Findings from stale-content runs carry "re-scan recommended".
   - Optional, tenant opt-in: when a critical template or rule lands, the
     platform triggers a pipeline re-run through the CI provider's API.
6. **Offline CI:** an `openctem content export` / `import` bundle step, with
   the signature verified.
7. **Security:**
   - fetch only from the platform, a mirror or signed public artifacts;
   - verify signature and digest before use;
   - packs are read-only in the container;
   - the content token is read-only and scoped to the tenant;
   - no secrets in logs.

### 3.6 Tenant content sources (private repositories and sites)

A tenant configures sources in the UI, through the API or as code. A source
produces one or more packs. Packs bind to tools **by kind, not by tool
name**, so the platform's tools and the tenant's own tools use them the same
way.

```yaml
content_sources:
  - name: acme-nuclei
    type: git
    url: https://gitlab.example.com/sec/nuclei-templates.git
    ref: main
    auth: { credential: gitlab-content-token }
    sync: { webhook: true, poll: 6h }
    packs:
      - { kind: nuclei-templates, path: templates/, exclude: ["**/dos/**"] }
  - name: acme-rules-site
    type: https
    url: https://rules.example.com/semgrep/latest.tar.gz
    integrity: { cosign_public_key: acme-rules-key }
    packs:
      - { kind: semgrep-rules, path: rules/ }
  - name: intranet-wordlists
    type: https
    url: https://files.corp.example/wordlists.tar.gz
    fetch_via: sensor
    integrity: { sha256: "…" }
    packs:
      - { kind: wordlist, path: . }
```

A step using it:

```yaml
content: { templates: { mode: merge, sources: [acme-nuclei], include: { tags: [cve, exposure] }, pin: commit } }
```

**Source types:**

| Type | Location | Authentication (least privilege, read-only) | Sync and pin |
|---|---|---|---|
| `git` | GitHub, GitLab, Bitbucket, self-hosted | Preferred: a GitHub App installation with read-only contents. Alternatives: a GitLab project or group access token or deploy token; an SSH deploy key (read-only); a fine-grained personal token as the last resort | `ref` is a branch, tag or commit. Sync on a push webhook (signature verified), with polling as fallback. A sync pins the resolved commit |
| `https` | An archive or a directory index | Header, basic, bearer or mTLS | **Integrity is required:** an expected sha256, or a tenant signing key (cosign or minisign) whose signature is verified |
| `oci` | A registry artifact | Registry credentials | Manifest digest |
| `s3` | Bucket and prefix | Role or keys | Object version or ETag + content digest |

**Credentials:**
- stored encrypted in the tenant credential store and referenced by name;
- never sent to sensors (except the `fetch_via: sensor` path below, where the
  sensor uses its own local credential configuration);
- rotation reminders;
- "last synced" and "last error" shown per source.

**Fetch path:**
- The platform fetches through the SSRF guard, public addresses only.
- An intranet-only source sets `fetch_via: sensor`. One of the tenant's own
  sensors, chosen by zone, fetches it under its local policy and egress
  profile, then uploads the bytes to the platform. The normal lint, classify
  and sign pipeline follows.
- Platform (shared) sensors never fetch tenant sources.

**Pack declaration and binding:**
- Each source declares packs with `kind`, `path` and include/exclude globs.
- Alternatively, an `openctem-content.yaml` at the repository root declares
  the packs itself; the platform configuration may narrow it, never widen it.
- Any tool whose `tool.yaml` declares a slot of that kind can use the pack,
  built-in or custom.
- A custom tool may declare a new namespaced kind (`x-acme/rules`); packs of
  that kind bind only to tools declaring it.

**Validation per kind:**
- Before a pack becomes usable, its kind's validator (template or rule
  validation, schema checks) runs in a sandbox on the platform side, with
  results per file in the UI.
- Tier classification, secret scanning and size limits apply as in §3.2.
- A new namespaced kind declares its validator as a tool of class `parser`
  run in the same sandbox, or gets only the generic checks (size, archive
  safety, secret scan).

**Security:**
- Least-privilege read-only credentials.
- Webhook secrets verified.
- Every source change audited.
- Approval required for sources whose packs classify as T2.
- A source and its packs belong to one tenant.

**Tests (mocked servers):**
- a private GitHub and a GitLab fetch with each authentication type;
- a webhook-triggered sync;
- an `https` source whose sha256 or signature does not match is refused;
- the `fetch_via: sensor` path, including a platform sensor refusing it;
- a namespaced kind binds only to the custom tool that declares it;
- a cross-tenant source or pack is never visible or delivered.

### 3.7 Isolation

- Tenant packs ship only to that tenant's sensors.
- Platform (shared) sensors run platform packs, plus tenant packs that
  passed the stricter lint (no T2 content) when the tenant policy allows it.
- Packs are mounted per task (RFC-060). A task sees only its run's packs.
- Custom templates move off `$TMPDIR` (closes C3).
- A digest from another tenant is never resolved: 404 in the API, refused
  by the sensor.
- Provenance: every finding carries `template_id` (or `rule_id`) and the
  pack digest, so a retest reproduces the exact content.

## 4. Use cases

| Use case | Flow | Test or procedure |
|---|---|---|
| Daily CVE rapid response | Upstream release → platform ingest + lint → canary pool of sensors → automatic promotion after health checks (template error rate, run success) → push → the automated-testing policy retests the affected assets | integration: canary promotion + push; retest uses the new digest |
| Compliance freeze | Scan policy `channel: pinned` with an expiry reminder; updates never apply to that policy | resolution test: pinned digest kept across a new release |
| Bad or malicious pack | Revoke a digest → sensors purge it → queued tasks using it fail fast `content_revoked` → automatic rollback to the previous good digest on the channel → admin alert, audited | revocation test |
| Tenant edits a custom pack | New digest → pushed only to that tenant's sensors | cross-tenant never delivered |
| Air-gapped sensor | `openctem content export` writes a signed offline bundle; `openctemio-sensor content import` verifies the signature and digests: same digests as online | bundle round-trip test |
| Low bandwidth / remote site | Chunked, content-addressed transfer (unchanged chunks reused across versions), sync windows, an optional regional mirror the operator runs (sensor → mirror; never peer-to-peer between tenants) | chunk reuse test |
| Sensor offline for weeks | On reconnect it reconciles first; jobs needing digests it lacks are not placed on it until it has them | placement test |
| Partial rollout | Placement prefers sensors holding the digests; a drift view per sensor; `SensorContentStale` alert | placement + alert rule |
| Storage limits | LRU GC that never evicts pinned digests | GC test |
| First boot | Warm-up sync before the sensor advertises content-dependent capabilities | manifest test |
| CI images (openctemio/ci) | §3.5: fetch at job start (platform with the OIDC token, or signed public OCI artifacts), cache by digest, freshness policy, SBOM re-matching on the platform | tests: stale baked content + fetch failure (`preferred` runs and marks `content_stale`, `required` fails); cache hit by digest; digests recorded in results; an SBOM re-match creates a finding for a new CVE with no CI run |
| Local development | `openctem content pull <pack>@<digest>` and `openctem content verify`; `openctem tool run --content templates=<dir>` for a tool author | CLI tests |
| Custom templates today (RFC-038 §6.12) | Become a tenant pack; the inline DSSE manifest is replaced by the pinned digest + pack signature; the `$TMPDIR` path is deleted | migration test: an existing custom template set runs unchanged |

## 5. Threat model

| Threat | Control |
|---|---|
| A malicious template runs code or attacks out of scope | Lint and tier classification; refused features (`code`, `javascript`, `headless`, `file`); tier ceiling; RFC-060 forwarder enforces scope whatever the template sends |
| Tampered pack in transit or at rest | DSSE signature + digest verified before storing and again at mount |
| Cross-tenant leakage of a custom pack | Tenant-scoped storage and delivery; per-task mounts; digest lookups tenant-scoped |
| Archive tricks (traversal, symlinks, bombs) | Safe unpack at ingest with caps; canonical tar; sensors receive only canonical packs |
| A source fetch abused as SSRF | Platform fetches through httpsec; private ranges refused unless marked internal by the platform operator |
| Secrets committed into a pack | Secret scan at ingest; a hit blocks the pack until acknowledged |
| A tool's own updater bypasses packs | Update flags refused; updaters disabled; RFC-060 forwarder refuses update endpoints |
| A sensor holds stale or revoked content | Desired state + revocation push; tasks fail fast with a reason; drift alert |

## 6. Phased plan

| Phase | Deliverable | Repos |
|---|---|---|
| K1 | `content:` slots in `tool.yaml` (validator, schema, `ctx.Content`, protocol `run.task.content`, exec placeholders); built-in tools declare their slots | sdk-go, sensor |
| K2 | Pack store: ingest, canonical archive, lint, classification, signing, API and permissions, audit; platform-managed upstream sources with channels | api |
| K3 | Desired state, push (v3 stream and v2 heartbeat), sensor prefetch, cache by digest, manifest by digest, GC | api, sdk-go, sensor |
| K4 | Composition in steps, policies and profiles; pin at run start; retests reuse digests; placement by cached digest | api, web |
| K5 | Tenant content sources (§3.6: git with app/token/deploy-key auth and webhooks, https with required integrity, oci, s3, `fetch_via: sensor`, binding by kind incl. namespaced kinds, per-kind validation); custom templates migrated; `$TMPDIR` path removed | api, sdk-go, sensor, web |
| K6 | Offline bundles, mirrors, CLI `content pull/verify` | sdk-go, sensor |
| K7 | CI: fetch at job start, cache by digest, freshness policy and `content_stale`, public signed content artifacts, `vuln-db` kind | ci, api |
| K8 | Platform SBOM re-matching against new advisories; "re-scan recommended"; opt-in pipeline re-run | api |

## 7. Decisions (owner delegated 2026-10-08)

| # | Decision |
|---|---|
| K-D1 | Content is a declared contract (`content:` slots); tools never fetch content |
| K-D2 | The platform is the only source of truth and the only fetcher of external sources (operator mirrors excepted) |
| K-D3 | Desired-state reconciliation + pin at dispatch; never "check latest" at run time |
| K-D4 | Content is code: lint, tier classification, signing, tenant isolation and audit apply to every pack |
| K-D5 | Retests reuse the original digests |
