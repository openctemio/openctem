# Content catalog

Design, threat model and decisions: [RFC-099](../rfcs/RFC-099-content-packages.md). This page describes what is
built.

| Part | Status |
|---|---|
| Package format, JSON schema, validator (`pkg/contentpkg`) | shipped |
| Signatures, signed index and revocation list, offline bundle reader and verifier (`pkg/contentpkg`) | shipped |
| Catalog: tables, offline import, install / update / pin / rollback / uninstall, approval option, audit | shipped |
| Private catalogs (organization and instance publishing, migration 002856) | shipped |
| First-party packages and the bundle generator (`pkg/contentpkg/firstparty`, `cmd/content-bundle`) | shipped |
| Console page (Settings > Content catalog, `/settings/content`) | shipped |
| Installed packs delivered to sensors (desired state) | designed |

## Trust

```
offline catalog root ──signs──► key set (version, ≤ 180 days, ≤ 8 online keys)
                                   │
                    online key ────┴──► statements · index (sequence, expiry) · revocation list (sequence, expiry)
publisher (Sigstore keyless) ─────────► artifact
```

- **Roots.** `contentpkg.PinnedRoots` (the release) plus `CONTENT_TRUST_ROOT_KEY_IDS` (comma-separated key ids,
  `SHA256:<hex>`). With no root every import is refused.
- **Publisher signatures** are verified offline with the Sigstore trusted root embedded in the release
  (`pkg/contentpkg/sigstore/trusted_root.json`); `CONTENT_SIGSTORE_TRUSTED_ROOT` names a newer file. Refresh the
  embedded copy from the Sigstore root-signing repository when Sigstore rotates a key.
- **Overrides are audited.** When either variable is set, the server logs a warning at startup and writes a
  high-severity admin audit row `content_catalog.trust_override` naming the extra roots and the SHA-256 of the
  replacement trusted root.

## Model (migration 002571)

| Table | What |
|---|---|
| `content_catalog_trust` | One row: the applied key set version, index sequence and digest, revocation list sequence and digest, expiries |
| `content_packages` | Package versions. `tenant_id` NULL: the instance catalog; set: an organization's private package. Manifest (raw bytes and JSON), digests, catalog statement, publisher signature and identity, tier, service use, revocation |
| `content_revocations` | Every applied revocation entry, kept |
| `content_installs` | Per organization and package id: installed version, previous version, pinned, `active`/`revoked` |
| `content_install_requests` | Pending and decided requests; a CHECK keeps the decider apart from the requester; one pending request per package |
| `content_catalog_settings` | The approval option per organization (no row: off) and a pending switch-off time |

## Import

`POST /api/v1/admin/content-catalog/import` (multipart `bundle`, `reason`, `totp_code`; super admin) streams the
bundle into `contentcatalog.Service.Import`:

1. `contentpkg.ReadBundle`: tar or tar.gz, in memory, at most 128 MiB and 4,096 entries, only regular files at
   known paths.
2. `contentpkg.Verify` against the applied state: key set (pinned root, version not below the applied one), index
   (signature, expiry, sequence above the applied one or the same bytes), revocation list (signature, sequence
   above the applied one or the same bytes), every package (manifest digest in the index, schema, catalog
   statement equal to the manifest, artifact digest and size, publisher signature with the exact identity).
   Revoked packages are left out and listed.
3. One transaction (`ApplyImport`) that re-checks the applied state under a row lock, stores the new versions (the
   same id and version with another manifest digest is refused), keeps the revocation entries, revokes the
   versions they name and the installations of those versions, and stores the new state. Any failure stores
   nothing.
4. Unpinned, active installations follow the newest compatible, non-revoked version that asks for no more
   permissions (tier, side effects, network class, hosts, credentials, data scopes) and keeps the license class,
   unless the organization requires approval. Each move is audited as `content_package.updated`.

The admin audit row (`content_catalog.import`, high) carries the reason, the index sequence and the counts.

Every read of an artifact goes through `contentpkg.CheckArtifact` (size, then SHA-256 against the signed
manifest); a source that fetches artifacts later (storage, a mirror, an online catalog) implements
`contentpkg.ArtifactSource` and is read only through `contentpkg.FetchArtifact`, which bounds the body and checks it.

## Installs

Routes and gates: [authorization matrix](authorization-matrix.md#content-catalog-apiv1content-rfc-099).

| Check at install, update, rollback and approval | Result |
|---|---|
| Version revoked (row or applied entry) | 422 |
| Platform release outside `compatibility.platform` | 422 |
| `license.service_use: false` without `acknowledge_license` | 422 (the acknowledgement is audited) |
| A dependency not installed at a version in range | 422 |
| An executable type (`sensors`, `tool-adapters`) while the revocation list is missing or past its expiry | 422 |
| Uninstall of a package another installation depends on | 422 |
| Another organization's installation or request | 404 |

- **Update** needs a newer version; **rollback** an older one (the previous version by default) and pins the
  installation. **Pin** stops automatic updates.
- **Approval option** (`PUT /settings`, `settings:write`): every install, update, rollback and uninstall becomes a
  request. Another member with `content:install` approves it; the request is checked again first and is marked
  `failed` with the reason when it can no longer be carried out. The decision and the change commit in one
  transaction.
- **Switching approval off waits 24 hours** (`approval_off_at`): until then requests are still required, and the
  organization's owners and administrators get a high-severity in-app notice so they can turn it back on, which
  cancels the switch-off. Turning approval on is immediate.
- Audit actions: `content_package.installed`, `updated`, `rolled_back`, `uninstalled`, `pinned`, `unpinned`,
  `requested`, `request_approved`, `request_rejected`, `request_canceled`, `content_catalog.settings_updated`.
  Each carries the version, artifact digest and origin; T2 and executable installs are high severity.

## Private catalogs

| | Organization | Instance |
|---|---|---|
| Who | a member with `content:publish` and a recent sign-in | a platform super administrator with a reason and a fresh console authenticator code |
| Route | `POST /api/v1/content/private-packages` (multipart `manifest`, `artifact`) | `POST /api/v1/admin/content-catalog/packages` |
| Namespace | the organization's slug | any non-reserved namespace not used by the signed catalog |
| Visible to | that organization only | every organization of the instance |
| Artifact | becomes one of the organization's content packs (lint, credential scan) | becomes a platform content pack; refused when lint leaves a file out |
| Statement | signed with the organization's content key | signed with the platform content key |
| Revoke | `POST /api/v1/content/private-packages/{ns}/{name}/{version}/revoke` | `POST /api/v1/admin/content-catalog/packages/revoke` (`package_id`, `version` in the body) |

- Types: rules, templates and wordlists (the types delivered as packs). The others need their importers first.
- The declared tier must be at least the tier lint finds; a private package never asks for credentials or data
  scopes.
- An id used by another origin in the same view is refused (`ErrIDTaken`); a signed bundle cannot take an id an
  instance package uses. Revoking a version revokes every installation of it.
- Audit: `content_package.published`, `content_package.revoked` (organization); admin audit rows
  `content_catalog.publish`, `content_catalog.revoke` (instance).

## Console page

Settings > Content catalog (`/settings/content`, needs `content:read`):

- **Catalog**: the imported packages with type, search and installed filters (server pagination). A row opens the
  package: its versions, what each asks for (tier, side effects, network, declared hosts, credentials, data
  scopes), the license and whether it allows use as a service, dependencies, revocation, and the signatures and
  provenance with copyable digests.
- **Actions** (shown with `content:install`): install (version, pin, license acknowledgement when service use is
  not allowed, note), update with what the new version asks for beyond the installed one highlighted, rollback,
  pin or unpin, uninstall. A 202 shows "request sent for approval"; a pending request hides further actions on that
  package. Writes need a recent sign-in: the console asks for it and retries.
- **Installed** and **Requests** tabs: pending requests first; another member approves or rejects (a reason is
  required to reject), the requester cancels.
- **Settings** tab: the approval option (`settings:write`). A pending switch-off shows its time and that turning
  approval back on cancels it.
- A banner warns when the signed index has expired or the revocation list is stale, and explains an instance with
  no trust root or no import yet.

The page hides what the member cannot do; the API enforces every gate.

## Key files

`pkg/contentpkg` (format, trust, bundle), `pkg/domain/contentcatalog`, `internal/app/contentcatalog`,
`internal/infra/postgres/content_catalog_repository.go`, `internal/infra/http/handler/content_catalog_handler.go`,
`internal/infra/http/handler/admin_content_catalog_handler.go`, `internal/infra/http/routes/content_catalog.go`,
`cmd/server/content_catalog.go`; console: `web/src/features/content-catalog`,
`web/src/app/(dashboard)/settings/content/page.tsx`. Tests: `pkg/contentpkg/*_test.go`,
`internal/infra/http/routes/content_catalog_db_test.go`.
