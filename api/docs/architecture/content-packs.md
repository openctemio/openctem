# Content packs: the pack store

Design, use cases and threat model: [RFC-061](../rfcs/RFC-061-content-packs.md).
This page describes what is built: the pack store for tenant uploads (phase K2)
and delivery to sensors by digest (part of K3). Composition in steps and pin at
run start (K4) and the other sources (K5) come later.

> **Not active yet (research/191 C-1).** No sensor syncs packs and no job
> references one, so a stored pack is not used by any scan and revoking it
> stops nothing; custom templates still travel inside each scan job. The
> console shows packs as "Stored, not delivered" with a notice until sensor
> delivery (RFC-061 K3 on the sensor side, research/191 WP10) ships.

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
   | `nuclei-templates` | Every YAML file goes through the custom-template validator (one YAML document per file). Code-class blocks are errors: `code`, `javascript`, `flow` (JavaScript run by the engine), `headless` and `file`. So are self-contained templates, unsafe regexes and more than 10,000 estimated requests per target. Workflow `template:` references and payload list files must name files of the same pack by a relative path that stays inside it; workflow `tags:` selectors are errors. A workflow that runs a refused template, or that loops, is refused with it. Other files are data. | Computed from the parsed document, never from author declarations (see below). T2 for out-of-band callbacks, state-changing requests (PUT/PATCH/DELETE, POST with a body), race requests, more than 25 threads or a non-numeric `threads`, fuzzing rules, and more than 500 estimated requests per target. T1 for dns/network/tcp/ssl/websocket/whois or payloads. A workflow takes the highest tier of what it runs, and at least T1. Otherwise T0. |
   | `semgrep-rules` | Every YAML file goes through the rules validator. | T0 |
   | `wordlist` | UTF-8 text with no NUL. Each line is at most 4096 bytes, and a pack holds at most 10 million lines. | T0 |
   | `x-<namespace>/<kind>` | Archive rules only. A warning says the kind has no linter. | T1 |

   A lint error refuses the pack with 422 `CONTENT_LINT_FAILED`; the lint report is in `details`.

   **Capability analysis** (`internal/app/template/capabilities.go`) runs on the decoded document, so block YAML, flow YAML, JSON, escaped, padded or differently cased keys and YAML merge keys all count the same. A key is matched with Unicode case folding, the way the engine matches JSON field names.
   - Out-of-band callbacks are found in every key and string value: the `interactsh` placeholder and matcher parts in any spelling (case, spaces, helper calls that split the word), and public callback domains. Text in YAML comments does not count.
   - `threads` and `race_count` are read as integers, floats or numeric strings. A templated value counts as unknown, which makes the template T2.
   - The estimated requests per target come from the structure: paths plus raw requests, times the payload combinations, times the race count. Payload combinations are the product of the lists for `clusterbomb` and the longest list otherwise; a payload file counts its non-empty lines. Declared counts such as `info.metadata.max-request` are ignored.
   - A single custom template (Settings > Scanning > Templates) is validated the same way but references nothing: `workflows` and payload files are errors there, because the engine would resolve them against its own template directory.
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

## Rule source snapshots

A [rule source](content-sources.md) sync stores each snapshot as a pack of
the organization (`source = git`, name = the source slug), signed with the same
key and linted the same way. A snapshot's pack is in the desired set
sensors receive only while that snapshot is its source's current one;
candidates, rejected, superseded and orphaned packs are left out. Snapshot
bytes count inside the organization's storage quota below (not the pack
count), and the organization's `content_storage_mb` limit caps them
separately; collected snapshots delete their pack and, when no other pack uses
it, the stored archive.

## Platform packs and channels

Migration 001568 adds platform packs, which are kept apart from tenant packs:

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

- the code-class blocks `code`, `javascript`, `flow`, `headless` and `file`;
- self-contained templates;
- unsafe regexes;
- templates above the request limit, and payload files that are not in the release;
- YAML files that are not templates (CI files, profiles);
- workflows that reference a file outside the release, select by tag, or run a left-out template.

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

## Delivery to sensors

Sensors get packs only from the platform, over the sensor channel (protocol v2 routes, also served in process for protocol v3), on the control read budget:

| Route | What |
|---|---|
| `GET /api/v2/sensor/content/desired` | The sensor's desired set: for an organization sensor its organization's active packs and the platform's packs on the `stable` channel, for a shared sensor the platform's `stable` packs only; each with digest, scope, size and the DSSE signature; plus the revoked digests. It has an `ETag` (a hash of the document). `If-None-Match` with the current one answers `304` with no body. |
| `GET /api/v2/sensor/content/packs/{digest}` | The canonical archive. Immutable: `ETag` is the digest, `Cache-Control: immutable`, and `Range` is supported. |
| `GET /api/v2/sensor/content/packs/{digest}/index` | The pack's files: `path`, `sha256`, `size`. |
| `GET /api/v2/sensor/content/packs/{digest}/files/{sha256}` | One file of the pack. |

- **What a sensor may read.** It reads only digests in its own desired set. Anything else is `404 content-not-found`: another organization's pack, a revoked one, an unknown digest, or a file that is not in the pack.
- **Shared sensors.** A shared sensor (one that serves several organizations) may read the content routes, in the *instance* scope: the platform's `stable` packs and nothing else. An organization's pack is `404` for it whatever job it holds, so one copy of a platform pack serves every organization on the box and nothing of one organization's is ever cached there. Organization templates and rules never reach a shared sensor ([RFC-061](../rfcs/RFC-061-content-packs.md) §3.7, [RFC-100](../rfcs/RFC-100-shared-sensors.md) §8).
- **Revocation latency.** The set is cached for 10 seconds per organization (and for the instance scope), so a delta install's many file requests do not recompute it, and a revocation takes effect within that time.
- **Content version.** The heartbeat answer carries `content_version`, the ETag of the sensor's own desired set, computed from the same cached set. A promotion to `stable`, a revocation or a new organization pack changes it, and the sensor then refreshes at once instead of waiting for its schedule.
- **Content keys.** The pairing response carries the keys a sensor verifies packs with ([Sensor pairing](sensor-pairing.md#content-keys)); a sensor never takes a key from these routes.
- **Archive cache.** Served archives are re-checked against their digest and kept in a 256 MiB in-process cache.
- **The sensor side** (sdk-go `contentcache`):
  - it never fetches a digest it holds;
  - it builds a new version from the files it holds plus only the changed ones, and checks the rebuilt archive against the signed digest;
  - it prefetches on a jittered schedule;
  - it counts hits, misses and bytes saved.
- **Measured** (integration test, 3 sensors × 2 runs, a 40-file pack with 2 files changed in the new version): the new version cost 30 KB instead of 372 KB of full downloads (92% less). Over both runs, traffic is 44% less than every sensor downloading every version in full, and upstream downloads drop from one per sensor to one per platform.

## Jobs that pin content

A scan or retest job names the packs it reads by digest, and the lists the platform generated for it travel inline (RFC-061 §3.7). The platform sets two members on the copy of the command a sensor receives, never on the stored command; a member a creator wrote is removed.

- **`content[]`**: `{slot, kind, scope, pack, digest, size, files, max_lines, signature}` per pack. `scope` is `platform` or `tenant` (which pinned key signs it), `files` are the pack files the slot uses (at most 64) and `signature` is the pack's DSSE envelope. The signed statement repeats `{slot, digest}` of each in order ([job signing, Content](job-signing.md#content)); the sensor mounts only those packs and checks each against its pinned keys.
- **`inputs[]`**: `{slot, purpose, sha256, lines, data_b64}` per generated list. `data_b64` is gzip, at most 256 KiB compressed, 512 KiB for all of a job's lists and 8 MiB expanded; `sha256` is that of the uncompressed list. A list is never stored as a pack and never cached: it is written to the task's own directory and erased with it.
- **Asking for a list.** A payload names the lists it needs in `wordlists`: `[{"slot": "labels", "purpose": "dns-labels"}]` (purposes `dns-labels`, `web-paths`, `web-files`, `api-routes`, `params`). The platform picks the pack: the run's depth selects the size class, standard `wordlists-s` and deep `wordlists-m` (100,000 and 1,000,000 lines at most), both the platform's pack on the `stable` channel; a passive run uses no list, and no class above medium is offered. `files` are the pack's files in the directory of the purpose (`dns/`, `paths/`, `files/`, `api/`, `params/`). A job that asks for a list the platform cannot pin (no stable pack, a pack that is not a wordlist, no list for the purpose) is failed with the reason, not run without it.
- **Generated lists.** For `dns-labels` the platform adds a list built from the organization's own active domain and subdomain names under the job's DNS targets: the labels left of the root, and the parts of a label (`api-v2-eu` gives `api`, `v2`, `eu` and `api-v2-eu`), most frequent first. Only that organization's rows are read (every query carries its tenant id) and nothing of another organization appears in the list. A list over the cap is cut by rank, so the most frequent labels stay. It is deterministic for a given set of names, so retries of one run agree. It may run on a shared sensor: the names are the organization's own targets, they are signed into the job and live only in the task directory.
- **Deliverability.** Before the signer is asked, every digest is checked: it must be a platform `stable` pack or, for an organization's own sensor, one of that organization's active packs. Another organization's digest, a revoked one and an unknown one are refused, and the command fails with `SIGNER_REFUSED` and the reason.
- **What the platform records.** The pinned pack digests and the sha256 and line count of each generated list are written to the API log when the job is planned, and the signing log holds the hash of every signed statement.

## API

The routes are under `/api/v1/content-packs`, take the tenant from the JWT and are gated by the `scanner_templates` module.

| Route | Permission |
|---|---|
| `GET /`, `GET /{id}`, `GET /{id}/download` (canonical tar, `Digest` header), `GET /signing-key` | `scans:content:read` |
| `POST /` (multipart: `name`, `version`, `kind`, `acknowledge_secrets`, `archive`), `POST /{id}/revoke` (`reason`) | `scans:content:write` + a recent sign-in |

A pack of another organization returns 404. The owner and admin roles hold both permissions (migration 001384).

Quotas: 500 uploaded packs and 2 GiB of stored archives per organization (rule source snapshot bytes count in the 2 GiB, snapshot packs not in the 500).
