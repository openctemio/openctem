# Import mappings

Design: [RFC-126](../rfcs/RFC-126-import-mappings.md). The language: ctis
`docs/mapping.md` (`openctem.io/mapping/v1`).

## What is shipped

| Part | State |
|---|---|
| ctis `importer/mapping`: CSV and XML inputs, `identity`, `Options.Observe` | shipped (ctis PR #76; the API pins that commit until a ctis release) |
| API: CRUD with versions, validate, preview, templates, audit | shipped |
| Import through `format=mapping:<ref>[@<version>]` on `POST /findings/imports` and `POST /ci/runs/{id}/results` | shipped |
| Web editor (sample, mapping table, live preview, versions) | its own pull request |
| `openctem-ci upload --format mapping:<name>` | openctemio/ci pull request |

## How it works

1. A person with `integrations:manage` writes a mapping in the editor,
   starting from a template (`GET /import-mappings/templates`).
2. `POST /import-mappings/preview` maps a sample, at most 5 MiB, and stores
   nothing. `importmapping.Service.PreviewDocument` compiles the document
   (`pkg/domain/importmapping.Compile`: the language, then the organization
   policy) and runs it with `Observe`. For every finding it computes the key
   ingest would store it under with `ingest.PreviewFingerprint`, on the
   stand-in asset `ingest.PreviewAssetID(type, value)`. Equal keys in one
   sample are an `identity_collision` warning.
3. `POST /import-mappings` stores version 1. `POST /{id}/versions` stores the
   next version and compares identities (`importmapping.IdentityChanged`):
   the declared members, the finding's asset, every member the server keys
   findings on (`fingerprintInputs`) and the blocks that pick the recipe.
   An identity change answers 409 `identity_change_unconfirmed` until
   `confirm_identity_change` is sent; the version is then stored with
   `identity_changed = true`. A new version keeps the mapping's `source`.
4. An upload names the mapping. The handler resolves it in the caller's
   organization (`resolveMappingFormat`, `Service.Resolve`), and
   re-compiles the stored version under today's policy.
   `findingimport.convertMapped` runs it with the upload limits:
   - tool `mapped:<name>`, report source type `manual`, coverage `partial`;
   - `min_severity` is applied, and a CI run's repository becomes the asset
     of records without one;
   - the receipt's format is `mapping:<name>@<n>`, and the asset source name
     is `mapped:<name>`.
   A committed upload is applied by the ingest worker, not in the request
   (RFC-122). Accept resolves the mapping in the caller's organization (the
   run's, for CI) and answers 400 `unknown_mapping` when it does not
   resolve. The queued job pins the exact mapping id and version
   (`mapping:<name>@<n>`), never "latest". The worker resolves that pin again
   in the job's own organization (the stored job row, never the envelope);
   a mapping deleted, renamed or replaced since, or one that no longer
   passes validation, fails the upload with the fixed code
   `mapping_unavailable`. It never falls back to another version or to
   another organization's mapping. A preview (`dry_run=true`) still runs in
   the request.
5. Ingest decides identity as for any report (RFC-043). Nothing closes:
   the handler refuses `coverage=full`, and `closeUncovered` closes nothing
   for an upload through a mapping.

## Data

Migration `003360_import_mappings`:

- `import_mappings`: per organization, unique `(tenant_id, name)`, with a
  `latest_version`;
- `import_mapping_versions`: `(mapping_id, version)`, with the document
  (jsonb, at most 256 KiB), `digest`, `identity` and `identity_changed`. Its
  foreign key `(tenant_id, mapping_id)` keeps a version in its mapping's
  organization.
- A new version bumps `latest_version` with a compare-and-set in the same
  transaction, so two concurrent saves cannot take one number.

## Permissions

| Route | Gate |
|---|---|
| `GET /import-mappings`, `/templates`, `/{id}`, `/{id}/versions/{version_id}` | `integrations:read` or `assets:import` |
| `POST /import-mappings`, `/verify`, `/{id}/versions`, `PATCH /{id}` | `integrations:manage` |
| `POST /import-mappings/preview` | `integrations:manage`, 20 per minute per organization |
| `DELETE /{id}` | `integrations:manage`, step-up |
| import with `format=mapping:` | the import route's own gate |

## Key files

- `pkg/domain/importmapping/importmapping.go`: policy (allowed targets,
  identity members, finding types), identity change, format parsing.
- `internal/app/importmapping/service.go`: service, preview and templates
  (`templates/*.json`).
- `internal/infra/postgres/import_mapping_repository.go`
- `internal/infra/http/handler/import_mapping_handler.go`,
  `import_mapping_format.go`; routes in
  `internal/infra/http/routes/import_mappings.go`.
- `internal/app/findingimport/convert.go` (`convertMapped`).
- `internal/app/ingest/preview_identity.go`.
