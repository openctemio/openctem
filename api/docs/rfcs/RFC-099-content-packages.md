# RFC-099: Content packages, signatures, revocation and the content catalog

| | |
|---|---|
| Status | Proposed (2026-10-15). Implemented: the package format (`package.yaml`, JSON schema, validator). Designed: signatures and trust, signed index and revocation list, the content catalog, first-party packages, the console |
| Scope | api, web |
| Related | RFC-061 (content packs), RFC-040 (mutual distrust, signed jobs), RFC-037 (versions and the sensor product catalog), RFC-072 (chunked feed transfer), RFC-094 (contracts only) |
| Schema | [`api/pkg/contentpkg/schema/package.v1.schema.json`](../../pkg/contentpkg/schema/package.v1.schema.json) |

## 1. Summary

Rules, templates, wordlists, scan profiles, report templates, playbooks, policy packs, tool adapters, sensor
products and feeds reach an instance today through different paths, each with its own trust story. This RFC gives
them one shape and one trust pipeline:

1. **One package format** (`openctem.io/package/v1`): a manifest (`package.yaml`) beside an artifact that is
   addressed by its SHA-256 digest. A published version never changes.
2. **Two signatures.** The publisher signs the artifact (Sigstore keyless, bound to a registered build identity).
   The catalog countersigns a statement after review, with a key that chains to an offline root pinned in the
   release. An instance requires both.
3. **Signed update metadata.** A signed index with a sequence (no rollback) and an expiry (no freeze), and a signed
   revocation list with the same properties. Both work without network access: they travel in the offline bundle.
4. **A content catalog in the core.** What an instance has (imported, verified packages), what each organization
   installed, pinned or rolled back, with a new permission, an audit trail and an optional approval step. Each
   organization and the instance itself can publish private packages that never leave the instance.
5. **First-party content as packages.** The official rules, the sensor product catalog and the feeds are listed as
   signed first-party packages, without changing how they are delivered.

Publishing by third parties, paid content and a hosted catalog service are out of scope here.

## 2. Problem

| # | Finding |
|---|---|
| P1 | Each kind of content has its own path and checks: content packs (RFC-061) are signed by the instance itself, sensor images are checked by the install snippet, feeds have their own key set, rules are fetched by tag |
| P2 | Nothing says what a piece of content is allowed to do (tier, network, credentials, data it reads) or under which licence it may be used by a service, in a form the instance can check before it is used |
| P3 | Nothing records which organization installed which version of shared content, who approved it, or lets it pin or roll back one |
| P4 | There is no signed, offline way to say "this version is bad, stop using it" across instances |
| P5 | An organization cannot share its own content between its teams in a reviewed, versioned way |

## 3. The package

### 3.1 Layout

```
packages/<namespace>/<name>/<version>/
  package.yaml              the manifest (§3.2), at most 64 KiB
  artifact                  the payload, when the artifact is a file (§3.3)
  publisher.sigstore.json   the publisher's signature (§4.2)
  statement.dsse.json       the catalog countersignature (§4.3)
```

Paths are derived from the package id and version, never read from data, so a bundle cannot point outside its own
tree.

### 3.2 Manifest

```yaml
apiVersion: openctem.io/package/v1
id: openctem/sast-rules            # <namespace>/<name>
version: 0.1.0                     # semantic version, immutable once published
type: rules                        # see the type table
title: Official SAST rules
summary: Opengrep rules maintained by the OpenCTEM team.
content_kind: semgrep-rules        # the RFC-061 pack kind, for types delivered as packs
artifact:
  media_type: application/gzip
  digest: sha256:4c7a...           # the content address
  size: 173226
compatibility:
  platform: ">=0.9.0, <2.0.0"
permissions:
  tier: T0                         # T0 passive, T1 active safe, T2 intrusive
  side_effects: none               # none | state-changing | destructive
  network: none                    # none | targets-only | declared-hosts
  declared_hosts: []
  credentials: []
  data_scopes: []                  # data beyond the task, e.g. findings:read
license:
  spdx: MIT
  service_use: true
  redistribution: true
dependencies:
  - id: openctem/wordlists-common
    version: ">=2.0.0, <3.0.0"
provenance:
  source_repository: https://github.com/openctemio/sast-rules
  source_revision: 0123456789abcdef0123456789abcdef01234567
  build_identity: https://github.com/openctemio/sast-rules/.github/workflows/release.yml@refs/tags/v0.1.0
  build_issuer: https://token.actions.githubusercontent.com
security_contact: security@openctem.io
```

| Field | Rules |
|---|---|
| `apiVersion` | exactly `openctem.io/package/v1`; unknown fields anywhere are refused |
| `id` | `<namespace>/<name>`, each `[a-z0-9][a-z0-9-]{0,38}[a-z0-9]` (1-40 characters). The namespace `openctem` and a short list of look-alikes (`official`, `openctemio`, `catalog`, `platform`, `system`) are reserved for first-party packages |
| `version` | semantic version 2.0 without build metadata (`1.4.0`, `2.0.0-rc.1`); at most 64 bytes. A version is immutable: the same id and version with another digest is refused |
| `type` | `rules`, `templates`, `wordlists`, `profiles`, `report-templates`, `playbooks`, `policy-packs`, `tool-adapters`, `sensors`, `feeds` |
| `title`, `summary` | plain text, at most 80 and 500 characters, no control characters; rendered as text, never as markup |
| `content_kind` | required for `rules`, `templates` and `wordlists` (they become RFC-061 packs): a known pack kind or `x-<ns>/<kind>`; forbidden for the other types |
| `artifact.media_type` | the content types in §3.3; `digest` is `sha256:<64 hex>`; `size` is the byte count (1 byte to 512 MiB) |
| `artifact.ref` | only for OCI artifacts: the repository, without a tag (`ghcr.io/openctemio/sensor`) |
| `compatibility.platform` | a version range (§3.4) the running platform release must satisfy; required |
| `compatibility.protocol` | for `sensors` and `tool-adapters`: the sensor protocol range (`>=3`) |
| `permissions` | required. Shown at install and enforced by the runtime (scope gate, tier ceilings, network classes). A manifest never grants anything by itself: the effective permission is the manifest ∩ the instance policy ∩ the job. `side_effects: destructive` requires `tier: T2`. `declared_hosts` is required and allowed only with `network: declared-hosts`, at most 16 host names |
| `license.spdx` | an SPDX expression or `LicenseRef-<id>`; `service_use` says whether the content may be used by a service that runs it for others (platform-hosted sensors); `redistribution` whether it may be mirrored |
| `dependencies` | at most 16, packages of content types only (an executable never depends on another publisher's executable); each `id` + `version` range |
| `provenance` | `build_identity` and `build_issuer` are required for the types signed with Sigstore (§4.2): they are the certificate identity and OIDC issuer the publisher signature must carry. `source_revision` is a 40 or 64 character commit id |
| `security_contact` | an e-mail address or an `https` URL |

### 3.3 Artifacts

| Type | `artifact.media_type` | What the digest covers |
|---|---|---|
| `rules`, `templates`, `wordlists` | `application/gzip`, `application/x-tar`, `application/vnd.openctem.content-pack.v1.tar` | the file as published. The instance turns it into an RFC-061 pack (canonical tar, lint, tier) and records both the package's artifact digest and the pack digest |
| `profiles`, `report-templates`, `playbooks`, `policy-packs` | `application/x-tar`, `application/gzip` | the file as published; each type gets its own importer before it can be installed (§8) |
| `sensors`, `tool-adapters` | `application/vnd.oci.image.index.v1+json`, `application/vnd.oci.image.manifest.v1+json` | the image index or manifest in `artifact.ref`; nothing is stored in the bundle |
| `feeds` | `application/vnd.openctem.feed-keyset+json` | the feed's signed key set (RFC-072); the feed data keep their own signed transfer |

### 3.4 Version ranges

A range is one or more comparators joined by commas, all of which must hold: `>=1.2.0, <2.0.0`. Comparators are
`=`, `>`, `>=`, `<`, `<=` followed by a semantic version (`>=3` means `>=3.0.0`). Pre-releases satisfy a range only
when a comparator names a pre-release of the same major, minor and patch. There is no `^`, `~` or `||`: ranges stay
easy to read in a review.

### 3.5 Content addressing

- The **artifact digest** is the content address of a package version. Installs, jobs and audit rows pin it.
- The **manifest digest** is the SHA-256 of the exact `package.yaml` bytes. The catalog statement names it, so a
  manifest cannot change after review.
- For content delivered as packs, the **pack digest** (RFC-061) is what sensors receive; the catalog records the
  mapping artifact digest → pack digest.

## 4. Signatures and trust

### 4.1 Keys

```
 offline catalog root (Ed25519, kept offline)  ── key id pinned in the platform release
        │ signs
        ▼
 catalog key set (version, issued, not after ≤ 180 days, ≤ 8 online keys)
        │ each online key signs
        ▼
 statements (one per package version) · the index · the revocation list
```

- The root's key id is pinned in the release (a constant list; an instance operator may add a root of their own
  with `CONTENT_TRUST_ROOT_KEY_IDS` for a private catalog source). No root configured means nothing can be
  imported: verification fails closed.
- The key set uses the feed key set format (`pkg/feedsign`) with its own payload type
  (`application/vnd.openctem.catalog-keyset+json`, kind `openctem.io/catalog-keyset/v1`). Its version is stored;
  an older key set is refused, so a removed online key cannot come back.
- **Rotation of an online key:** publish a key set with a higher version that lists the new key (and, for an
  overlap, the old one). Removing a key from the key set is how a compromised online key is revoked.
- **Rotation of the root:** the next root's key id ships in the pinned list of a release before the old root
  signs its last key set; once instances run that release, the new root signs the key sets. A compromised root
  needs an emergency release that drops it.
- The catalog keys are a separate key family. They are never derived from `APP_ENCRYPTION_KEY` or the content pack
  master key. An instance never holds a catalog private key: it only verifies.

### 4.2 Publisher signature

- `publisher.sigstore.json` is a Sigstore bundle (v0.3, keyless) over the artifact bytes: what `cosign sign-blob
  --bundle` writes.
- The instance verifies it offline against the Sigstore trusted root shipped in the release (or the file named by
  `CONTENT_SIGSTORE_TRUSTED_ROOT`):
  - certificate chain to the Fulcio roots, valid at the signing time;
  - a transparency log entry (signed entry timestamp) for the signature;
  - the certificate identity equals `provenance.build_identity` and its issuer equals `provenance.build_issuer`,
    both exactly, and both equal what the catalog statement names.
- OCI artifacts (`sensors`, `tool-adapters`) are signed in their registry. The instance checks the catalog
  statement and the pinned image digest; the image signature itself is checked on the host where the image is
  pulled, by the install snippets, against the same build identity (RFC-037).
- Feed packages are signed by the feed's own offline root (RFC-072); the package pins that key set.

### 4.3 Catalog statement (countersignature)

`statement.dsse.json` is a DSSE envelope, payload type `application/vnd.openctem.package-statement+json`, signed by
an online key of the key set:

```json
{
  "kind": "openctem.io/package-statement/v1",
  "id": "openctem/sast-rules",
  "version": "0.1.0",
  "type": "rules",
  "manifest_digest": "sha256:…",
  "artifact": {"media_type": "application/gzip", "digest": "sha256:…", "size": 173226},
  "permissions": {"tier": "T0", "side_effects": "none", "network": "none"},
  "license": {"spdx": "MIT", "service_use": true, "redistribution": true},
  "publisher": {"identity": "https://github.com/…/release.yml@refs/tags/v0.1.0",
                "issuer": "https://token.actions.githubusercontent.com"},
  "origin": "first-party",
  "reviewed_at": "2026-10-15T00:00:00Z"
}
```

Every field must equal the manifest. The statement is what was reviewed: the permissions and licence shown at
install are the statement's, and a manifest that differs is refused, so a publisher cannot change a reviewed
package.

### 4.4 Signed index

`index.dsse.json`, payload type `application/vnd.openctem.package-index+json`, signed by an online key:

```json
{"kind": "openctem.io/package-index/v1", "sequence": 42,
 "issued_at": "…", "expires_at": "…",
 "packages": [{"id": "openctem/sast-rules", "version": "0.1.0",
               "manifest_digest": "sha256:…", "artifact_digest": "sha256:…"}]}
```

- **No rollback:** the sequence must be higher than the last applied one. The same sequence is accepted again
  only with byte-identical contents (a repeated import is a no-op).
- **No freeze:** an index past `expires_at` is refused. Validity is at most 90 days.
- Every package of the bundle must be in the index with the same digests, and every index entry must be in the
  bundle. A bundle can hold a subset of the catalog: an index lists what the bundle carries.

### 4.5 Signed revocation list

`revocations.dsse.json`, payload type `application/vnd.openctem.package-revocations+json`:

```json
{"kind": "openctem.io/package-revocations/v1", "sequence": 7,
 "issued_at": "…", "expires_at": "…",
 "entries": [{"id": "acme/http-pack", "version": "1.4.0", "reason": "malicious update",
              "severity": "critical", "revoked_at": "…"},
             {"digest": "sha256:…", "reason": "…", "severity": "high", "revoked_at": "…"}]}
```

- An entry names a package id (every version), an id and a version, or an artifact digest.
- The list is a full snapshot with its own sequence (no rollback). Validity is at most 30 days.
- It ships in every bundle, so an instance without network access receives it with each import.
- Applying it marks matching packages revoked, revokes every installation of them and the packs they delivered, so
  sensors drop them at their next desired-state read (RFC-061 delivery lists revoked digests). Running content
  stops; nothing else in a scan stops.
- Entries are kept: an older bundle can never bring a revoked package back.
- **A stale list** (past its expiry): every page of the catalog warns the administrators, and new installs of
  executable types (`sensors`, `tool-adapters`) are refused. Installed content keeps working, except what is
  revoked.

### 4.6 What is refused by default

| Case | Result |
|---|---|
| No signature, a signature by an unknown key, a statement that does not match the manifest | refused |
| Artifact bytes that do not match the digest (a tampered package) | refused |
| Index or key set expired; index or revocation list with a lower sequence; key set with a lower version | refused |
| Publisher certificate identity or issuer other than the manifest and statement name | refused |
| A revoked package (by id, id and version, or digest) | refused at import and at install |
| An incompatible platform range | refused at install |

There is no switch that accepts unsigned content. Private packages (§5.3) are signed by the instance itself.

## 5. The content catalog

### 5.1 Model

| Table | Holds |
|---|---|
| `content_catalog_trust` | One row per instance: the applied key set version, index sequence and expiry, revocation list sequence and expiry |
| `content_packages` | One row per package version the instance has: id, version, type, manifest, digests, statement, publisher identity, origin (`first-party`, `instance`, `organization`), the pack it delivered, revocation. `tenant_id` is empty for the instance catalog and set for an organization's private packages |
| `content_revocations` | The entries of the last applied revocation list |
| `content_installs` | Per organization and package id: the installed version, the previous version, pinned or following, status |
| `content_install_requests` | Per organization: pending install, update, rollback and uninstall requests when approval is on |

### 5.2 Install, update, pin, rollback

- **Install** a package version for the organization. Its dependencies must already be installed at a version in
  range; its platform range must hold; a package whose licence says `service_use: false` needs an explicit
  acknowledgement, recorded in the audit row.
- **Update** to a newer version, **roll back** to the previous (or a chosen older) version, **uninstall**. A
  package another installed package depends on cannot be uninstalled.
- **Pin** stops updates. An unpinned installation follows the newest compatible version when the instance imports
  one, unless the new version asks for more permissions (a higher tier, wider network, new credentials or data
  scopes) or approval is on: then the console shows "update available" and a person decides. A rollback pins.
- **Approval option** (organization setting, off by default): every install, update, rollback and uninstall
  becomes a request. Another member with the install permission approves it; nobody approves their own request.
  The request is re-checked at approval (still not revoked, still compatible).
- Every action is audited with the package id, version and artifact digest.

### 5.3 Private catalogs

- **Organization:** a member with `content:publish` uploads `package.yaml` and the artifact. The instance checks
  the manifest, the digest, lints the content like any RFC-061 pack and signs a statement with the organization's
  content key. The package is visible and installable only in that organization. Reserved namespaces are refused.
- **Instance:** a platform super administrator publishes the same way through the admin console; the statement is
  signed with the platform content key and the package is visible to every organization of the instance.
- Private packages never leave the instance and are never sent to any outside service.

### 5.4 Permissions

| Permission | Allows |
|---|---|
| `content:read` | browse the catalog, the installed packages, the trust status |
| `content:install` | install, update, pin, roll back, uninstall; approve or reject someone else's request |
| `content:publish` | publish and revoke the organization's private packages (with a recent sign-in) |

Owners and administrators hold all three, members and viewers hold `content:read`. Changing the approval setting
needs the organization settings permission. Importing a bundle and publishing instance packages is a platform
super administrator action (a reason and a fresh console authenticator code), like importing platform content
packs.

### 5.5 Offline import

A bundle is one tar file:

```
keyset.dsse.json
index.dsse.json
revocations.dsse.json
packages/<namespace>/<name>/<version>/{package.yaml, artifact, publisher.sigstore.json, statement.dsse.json}
```

Import order: key set → index → revocation list → every package (manifest, digest, statement, publisher signature)
→ one transaction that stores the packages, the trust state and the revocations, revokes what the new list names
and moves unpinned installations forward. Any failure stores nothing. The bundle is read in memory with bounds
(128 MiB, 4,096 entries, file sizes per role) and never extracted to disk.

## 6. First-party packages

| Source | Package | Artifact | Publisher signature |
|---|---|---|---|
| `openctemio/sast-rules` releases | `openctem/sast-rules`, `rules`, `semgrep-rules` | the release tarball | the release's Sigstore bundle, unchanged |
| The sensor product catalog (`versions.yaml`) | `openctem/<product>`, `sensors` | the image digest of the `latest` release | the image signature in the registry (`release_identity`) |
| The program and vulnerability feeds | `openctem/program-feed`, `openctem/vulnerability-feed`, `feeds` | the feed key set | the feed root (RFC-072) |

A generator builds the first-party bundle from these sources and the catalog key signs it in the release
pipeline. Delivery does not change: rules, images and feeds keep their current paths; the catalog adds the signed
listing, the provenance, the revocation path and per-organization install state on top.

## 7. Threat model

| Threat | Control |
|---|---|
| A tampered artifact or manifest (in transit, on a mirror, on disk) | Artifact digest in the manifest, manifest digest in the statement, both signed; verified at import |
| A compromised catalog online key | It cannot sign as a publisher (the publisher signature is separate); it is removed by a new key set version, which cannot be rolled back |
| A compromised publisher account or build | It cannot pass review alone: the instance requires the catalog statement, whose permissions win |
| A malicious update of a good package | Versions are immutable and installs pin digests; permission increases need a person; the revocation list stops it |
| A rollback or freeze of the update channel | Index and revocation sequences, expiries, key set versions |
| Typosquatting and impersonation | Reserved namespaces, ids always `namespace/name`, first-party origin shown from the statement, not the manifest |
| Cross-organization access | Private packages, installs and requests carry `tenant_id` in every query; another organization's package answers 404 |
| A member installs content alone where the organization wants four eyes | The approval option; the requester can never approve their own request |
| Hostile bundle files attack the importer | Bounded in-memory reading, no extraction, strict JSON and YAML decoding with size caps, fuzz tests |
| Content does more than declared | The manifest is never a grant: the scope gate, tier ceilings, network classes and signed jobs apply to every run |

## 8. Phased plan

| Step | Deliverable |
|---|---|
| 1 | Package format: this RFC, the JSON schema, the validator |
| 2 | Trust: catalog key set, statements, publisher keyless verification, signed index and revocation list, the offline bundle reader |
| 3 | The catalog: tables, import, install / update / pin / rollback / uninstall, approval, audit, private packages |
| 4 | First-party packages and the bundle generator |
| 5 | The console Content page |
| Later | Importers for profiles, report templates, playbooks and policy packs; an online catalog source; sensor-side verification for offline sensor mirrors (RFC-061 K6) |

## 9. Decisions

| # | Decision |
|---|---|
| D1 | One format for every kind of content; versions are immutable and addressed by digest |
| D2 | Two signatures: the publisher's (keyless, bound to a build identity) and the catalog countersignature; the instance requires both |
| D3 | The catalog root is offline and pinned in the release; online keys rotate through versioned key sets |
| D4 | Index and revocation list carry a sequence and an expiry; a stale revocation list blocks new executable installs only |
| D5 | Nothing unsigned, expired or revoked is accepted; there is no switch to accept it |
| D6 | Installs are per organization, with a new permission, an audit row per action and optional four-eyes approval |
| D7 | Private catalogs per organization and per instance never leave the instance |
| D8 | Sensors receive packs re-signed by the platform, never packages: verification of packages lives in the core |
