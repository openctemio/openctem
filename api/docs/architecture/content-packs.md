# Content packs: the pack store

Design, use cases and threat model: [RFC-061](../rfcs/RFC-061-content-packs.md).
This page describes what is built: the pack store for tenant uploads (phase K2).
Delivery to sensors (K3), composition in steps (K4) and the other sources (K5) come later.

## Model

| Table | Key | What |
|---|---|---|
| `content_pack_blobs` | `(tenant_id, digest)` | One canonical archive per organization and digest. It is stored in that organization's namespace of the operator file storage (`STORAGE_PROVIDER`). |
| `content_packs` | `id`; unique `(tenant_id, name, version)` | A named, versioned pack over one blob, linked by the composite foreign key `(tenant_id, digest)`. A pack is immutable except for revocation. |

- Blobs are never shared between organizations. The same bytes uploaded by two organizations are two blobs, so looking up a digest cannot reveal what another organization holds.
- A blob that a pack uses cannot be deleted (`ON DELETE RESTRICT`).
- Deleting an organization erases its storage namespace and its rows.

## Ingest

Code: `pkg/domain/contentpack` (archive, signing) and `internal/app/contentpack` (lint, service).

1. **Archive.** The archive is a tar or tar.gz of at most 32 MiB uploaded. It may hold at most 64 MiB of files, 10,000 files and 8 MiB per file, with paths of at most 16 levels and 255 bytes.
   - Allowed entries: regular files and directories only.
   - Refused: links, devices, FIFOs, absolute paths, `..`, backslashes, control characters, unclean paths, case-folded duplicates, and a path that is both a file and a directory.
   - Each limit is checked before the bytes it covers are read.
2. **Canonical form.** Files are sorted by path. Each has mode 0644, owner 0:0, no user or group names and the epoch as its modification time. The digest is `sha256:` of the canonical tar.
3. **Lint per kind.**

   | Kind | Lint | Tier |
   |---|---|---|
   | `nuclei-templates` | Every YAML file goes through the custom-template validator. The `code`, `javascript`, `headless` and `file` protocols, self-contained templates and unsafe regexes are errors. Other files are data. | T2 for interactsh, `flow`, race requests, more than 25 threads, PUT/PATCH/DELETE, or POST with a body. T1 for dns/network/tcp/ssl/websocket/whois, payloads or workflows. Otherwise T0. |
   | `semgrep-rules` | Every YAML file goes through the rules validator. | T0 |
   | `wordlist` | UTF-8 text with no NUL. Each line is at most 4096 bytes, and a pack holds at most 10 million lines. | T0 |
   | `x-<namespace>/<kind>` | Archive rules only. A warning says the kind has no linter. | T1 |

   A lint error refuses the pack with 422 `CONTENT_LINT_FAILED`; the lint report is in `details`.
4. **Credential scan.** Every UTF-8 file is checked for well-known credential shapes (`evidence.CredentialShapes`: private keys, cloud and forge tokens, JWTs). The report records only the kind and path, never the value.
   - A hit refuses the pack with 422 `CONTENT_SECRETS_FOUND`.
   - The pack is stored only when the uploader sends `acknowledge_secrets=true`. That is recorded in the lint report and audited at high severity.
5. **Signing.** The platform signs a DSSE statement (`openctem.content-pack/v1`) with the organization's content key. The statement holds the tenant, pack id, name, version, kind, digest, size, file count, tier and time.
   - Each organization's key is an Ed25519 key derived by HKDF from `APP_CONTENT_SIGNING_KEY`. When that is unset, it is derived from `APP_ENCRYPTION_KEY` under its own label.
   - This key family is separate from the template-manifest, job-signing and sensor-CA keys. A test checks that the content key and the template key differ even when they come from the same master.
   - With no key configured, uploads are refused with 503; an unsigned pack is never stored.
6. **Store.** The blob is stored once per digest, then the pack row is written. A concurrent upload of the same digest deletes its unused object.
7. **Audit.** `content_pack.created` is recorded at medium severity, or high when secrets were acknowledged. `content_pack.revoked` is recorded at high severity.

**Isolation of ingest.** Ingest runs only Go parsers (tar, gzip, YAML), entirely in memory.
- It never writes an extracted file to disk and never executes anything.
- Every input is bounded by the limits above. At most 2 ingests run at once, and each must finish within 60 s; lint stops when that time runs out.
- Tenant content can reach code only through the parsers. The sensor-side sandbox (RFC-060) is where content is used.
- Fuzz tests (`FuzzCanonicalize`, `FuzzLint`) run the archive and template parsers on arbitrary input.

Ingest stays in the API process, owner decision 2026-10-08. A separate process would buy little when the input is only parsed by memory-safe Go code that runs no external program. If a linter ever needs an external tool, ingest moves to an isolated process (no network, no credentials, its own rlimits) first.

Reading an archive back re-checks it against its digest. Tampered storage returns 500 and is never served.

## Platform packs and channels

Migration 001546 adds platform packs, which are kept apart from tenant packs:

- `platform_content_pack_blobs` is keyed by digest.
- `platform_content_packs` is unique by name and version.
- `platform_content_channels` holds a `stable` and a `canary` pointer per name. The composite foreign key `(pack_id, name)` means a channel can only name a pack of its own name.

No tenant statement touches these tables. The archives live in the `platform-content` storage namespace, which is not a tenant id, so erasing an organization never reaches it.

**Ingest.** A super admin uploads a pack, or imports an upstream release by `https` URL.

- An import requires the release's `sha256` and checks it before anything is parsed.
- The fetch goes through the SSRF guard: public addresses only, checked at dial time.
- Limits: up to 128 MiB fetched or uploaded, 384 MiB of files, 60,000 files. One platform ingest runs at a time, with a 5 minute limit.
- The pack is signed with the **platform content key**: a separate HKDF label from the tenant keys, with statement `scope: "platform"`. A tenant statement cannot carry that scope, and a tenant key never verifies a platform pack.

**Upstream lint.** A file that fails lint is left out of the pack and listed as a warning (`lint.excluded` counts them). The release as a whole is not refused, and sensors never receive the left-out files. Left out:

- the `code`, `javascript`, `headless` and `file` protocols;
- self-contained templates;
- unsafe regexes;
- YAML files that are not templates (CI files, profiles);
- workflows.

Attack payloads in a template's requests (`/etc/passwd`, shell fragments) are what detection templates send to their targets. The custom-template text check refuses them; for upstream packs they make the template T2 instead.

Measured with nuclei-templates v10.5.0 (9.9 MB tar.gz, 15,325 entries):

- 11,329 files were kept and 3,084 left out;
- 10,996 templates, tier T2;
- a 47 MB canonical archive;
- 14 s on one core, about 430 MB of resident memory.

**Channels.** A super admin points `stable` or `canary` of a name at an active pack. Revoking a pack moves every channel that names it to the newest older active pack of the name, or removes the channel when there is none. This happens in the same transaction.

Routes:
- `/api/v1/admin/content-packs`: any admin reads. Upload, `import`, `{id}/revoke` and `channels/{channel}` change what every organization's platform sensors may run, so each needs:
  - a super admin;
  - a `reason`;
  - a fresh console authenticator code (`totp_code`, checked by the shared console step-up).

  Each write records an admin audit row at high severity with the reason.
- `/api/v1/platform-content-packs`: read-only for organizations, with `scans:content:read`.

## API

The routes are under `/api/v1/content-packs`, take the tenant from the JWT and are gated by the `scanner_templates` module.

| Route | Permission |
|---|---|
| `GET /`, `GET /{id}`, `GET /{id}/download` (canonical tar, `Digest` header), `GET /signing-key` | `scans:content:read` |
| `POST /` (multipart: `name`, `version`, `kind`, `acknowledge_secrets`, `archive`), `POST /{id}/revoke` (`reason`) | `scans:content:write` + a recent sign-in |

A pack of another organization returns 404. The owner and admin roles hold both permissions (migration 001384).

Quotas: 500 packs and 2 GiB of stored archives per organization.
