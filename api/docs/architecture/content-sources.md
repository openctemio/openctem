# Rule sources

Related: [content packs](content-packs.md) (the store snapshots live in),
[rule sources at scan time](rule-sources.md) (what a scan runs today),
[limits](limits.md), [authorization matrix](authorization-matrix.md).

A **rule source** is where the platform gets rules, templates or wordlists
from: today a git repository over https, such as a company's own GitLab
project of opengrep rules. The **platform is the only fetcher**. Sensors, CI
and developer laptops never fetch rules upstream; they receive snapshots from
the platform by digest. A sync resolves the ref to a commit, builds a
canonical archive, lints it, signs it and stores it as an immutable
**snapshot**. A new snapshot is a **candidate** until it is promoted; each
source keeps a **current** and a **previous** snapshot, so a rollback is one
call.

> **Shipped / not yet.** Built: sources, sync (schedule, Sync now, webhook),
> candidates with a rule diff, automatic and reviewed promotion, rollback,
> Test, credentials, CA per source, limits, the API below and the tenant view
> of platform sources. **Not yet:** scans and CI do not use snapshots (an
> ordered source list on scan profiles and CI settings, and the content
> manifest in the job, come next), platform sources are created only in the
> database (the admin console and their sync come next), the console page,
> the `https-archive` and `upload` origins, and the `proxy` storage mode.
> Until then a scan still runs the custom templates it names
> ([rule-sources.md](rule-sources.md)).

## Model

| Table | What |
|---|---|
| `content_sources` | One source. `scope` is `tenant` (an organization's own, `tenant_id` set) or `platform` (`tenant_id` NULL, offered to organizations). Kind (`semgrep-rules`, `nuclei-templates`, `wordlist`), origin (`git`; `https-archive`, `upload` and `catalog` are reserved), URL, ref (branch, tag or a full commit SHA), path, fetch credential (encrypted), CA bundle, license, promotion policy, schedule, webhook secret hash, storage mode (`mirror`), current and previous snapshot, last sync outcome. |
| `content_source_snapshots` | One snapshot: upstream revision (a commit SHA for git), digest, the content pack it is stored as (`content_pack_id` for a tenant source, `platform_pack_id` for a platform source), size, file index (`path`, `sha256`, `size`), rule list (`id`, `sha256` of the rule's own definition, `path`), tier, lint report, license (`license_spdx`, `service_use`, `redistribution`), the DSSE signature, the diff against the source's current snapshot, the promotion checks and the state (`candidate`, `promoted`, `superseded`, `rejected`). Unique per source and digest. |

- Composite foreign keys keep a snapshot in its source's scope and organization, and a tenant snapshot's pack in the same organization.
- The snapshot record (commit, file index, rule ids, digest, signature) is complete on its own, and its pack reference is optional, so the other storage modes need no new columns.
- `storage_mode` is `mirror` (the platform fetches and keeps every retained snapshot), `proxy` (the platform fetches and caches) or `tenant_hosted` (the bytes stay in the organization's network, the platform keeps only the signed pin record). **Only `mirror` is accepted today**; the sync worker claims mirror sources only.
- `rule_namespace` prefixes the source's rule ids. The server sets it at create and a trigger refuses any change, because finding fingerprints hash the full rule id: an organization source's rules are `<slug>:<rule-id>`, a platform source's `@<slug>:<rule-id>`, an official platform source's keep their ids. A slug is 2-40 of `a-z`, `0-9` and `-` (starting and ending with a letter or digit); `@` is allowed only on platform rows, and `/` and `:` never, so a platform source or another namespace (`<publisher>/<package>`) can never collide with an organization's slug. Slugs are unique per organization and among platform sources. A rule id longer than 160 characters refuses the sync, so the full key fits a finding's rule id.

## Owner scopes

| | Organization source | Platform source |
|---|---|---|
| Managed by | the organization (`scans:sources:*`) | platform administrators (admin console, next) |
| Seen by | that organization, in full except the credential | every organization it is offered to (`availability`: `default_on`, `opt_in`; `hidden` is offered to nobody), as a projection |
| Signed with | the organization's content key | the platform content key |
| Counts against the organization's limits | yes | never |

The **projection** of a platform source holds its name, slug, namespace,
kind, description, license, availability, official flag, current and previous
snapshot ids and a sync health of `ok`, `degraded` or `pending`. It never holds
the URL, credential, CA, schedule, webhook, storage mode or error text (which
can name internal hosts). Snapshots and their rule lists and diffs are
readable. Every organization route that changes a platform source answers 403;
a hidden one, like any id the organization cannot see, answers 404. In the
repository, every organization statement carries `tenant_id = $n`, which a
platform row (`tenant_id` NULL) never matches; only the visible reads add
`OR (tenant_id IS NULL AND availability <> 'hidden')`.

## Sync

The `content-source-sync` controller runs every minute on every API replica.
It takes a fetch slot (see Resource limits), then claims **one** due source
at a time with `FOR UPDATE SKIP LOCKED` and a 15-minute lease (three times
the 5-minute sync bound), and syncs up to five sources per run, so a source is
synced by one replica at a time and a later source of a batch is never leased
before its turn. The outcome is saved only while the source's lease is still
the claim's: a sync whose claim expired writes nothing. A Sync now, webhook or
change made after the claim stays queued (the request is cleared only when it
predates the claim). The claim is fair across organizations: the organization
claimed or synced longest ago goes first and, within one, a requested sync
before a scheduled one, so one organization's requests take one claim per
round, not the whole run:

- **Schedule**: every `sync_interval_minutes` (default 60, `0` turns it off), plus a jitter of up to a tenth of the interval (at most 5 minutes). The shortest interval is the installation's floor of 5 minutes, or the organization's limit `content_sync_floor_minutes` when higher.
- **Sync now** (`POST /{id}/sync`) and a **webhook** call queue a sync for the next run.
- An organization that turned the Rule Sources module off is not synced.

One sync, bounded to 5 minutes:

1. **Fetch.** A bare clone of the ref (shallow for a branch or tag; a commit SHA needs the history that holds it) into a temporary directory, aborted past 200 MB. The files under the path are read from the commit's tree, never from a checkout: only regular blobs; a symlink or submodule is skipped and reported; a Git LFS pointer refuses the sync. Limits are those of a content pack (10,000 files, 8 MiB per file, 64 MiB in all).
2. **Archive and lint.** The files become a canonical archive (sorted, fixed modes and times); its sha256 is the digest. The content pack linter runs ([content packs](content-packs.md)): a lint error or a credential-shaped value refuses the sync, and the lint report is kept on the source.
3. **Unchanged?** A digest the source already has stores nothing.
4. **Limits.** The snapshot must fit `content_snapshot_max_mb`, and the organization's snapshots `content_storage_mb`.
5. **Store.** The archive is stored and signed as a content pack (name: the slug; version: commit and digest prefixes), with the key chosen from the source's owner, never from a request.
6. **Diff and checks.** Against the current snapshot: rules added, removed and changed (by the hash of each rule's definition), tier and license change.
7. **Promote.** Under the `auto` policy a candidate is promoted when every check passes. Older candidates of the source are superseded.

A refused or failed sync leaves the current snapshot as it is; the source
shows the error and its lint report, and the failure is audited once per run
of failures.

### Promotion checks

A candidate is **not** promoted automatically when:

| Check | Why |
|---|---|
| `POLICY_REVIEW` | the source's policy is `review` (needs the `content_sources.review_policy` feature to set) |
| `TIER_RAISED` | its tier is above the current snapshot's (the first snapshot is compared with T0); such a candidate **always needs review**, whatever the policy |
| `LICENSE_CHANGED` | the repository's LICENSE changed |
| `LICENSE_NO_SERVICE` | the license forbids offering the rules as a service |
| `MASS_REMOVAL` | it removes more than a fifth of the rules (and more than five) |
| `DUPLICATE_RULE_IDS` | two definitions share an id |

Promoting a candidate (`POST /{id}/snapshots/{snapshot_id}/approve`) needs
`scans:sources:approve` and a recent sign-in. When the candidate needs review,
no member who changed the configuration it was synced from can promote it:
every snapshot records the members who changed what the source fetches (URL,
ref, path, CA, credential or policy) since the previous synced snapshot
(`config_authors`), and the member who last changed it (`config_changed_by`)
is refused too, as is a caller without a user: **four-eyes**. So a second
member's later, unrelated edit never frees the first to approve their own
change. Switching the promotion policy from `review` to `auto` needs
`scans:sources:approve`, not only `scans:sources:write`: turning review off
lets the next sync promote on its own. Promotion makes the candidate
current, the current one previous, and supersedes the old previous.
**Rollback** swaps current and previous. **Reject** closes a candidate.

Delivery is positive: a snapshot's pack is in the organization's desired
content set for sensors only while that snapshot is its source's **current**
one. Candidates (also those a newer commit superseded without anyone
promoting them), rejected and collected snapshots, and orphan packs left by a
failed sync or a failed cleanup are never delivered, whatever the state of the
cleanup. A failed snapshot insert deletes its pack at once.

### Collection (mirror storage)

Hourly, superseded and rejected snapshots older than a day that are neither
current nor previous are deleted with their pack, and the stored archive when
no other pack uses it. A pack whose delete failed stays undeliverable and is
removed the next hour as an orphan (a snapshot pack no snapshot references,
older than an hour).

## Credentials, CA and private hosts

- **Write-only credential.** `PUT /{id}/credential` takes a username and a token; the token is sealed with the installation key (`APP_ENCRYPTION_KEY`, rotated by `cmd/rekey`) together with the source id, the organization and the host, and is never returned: responses carry only whether one is set, the username, the last four characters and the time. A sealed value copied to another row, or used after the host changed, does not open, and the sync fails.
- **Username by token type.** Without a username: a GitLab deploy token (`gldt-`) is refused (it needs the username it was created with), other GitLab tokens use `oauth2`, GitHub tokens `x-access-token`, anything else `oauth2`.
- **Host change clears the credential**, so a stored token is only ever sent to the host it was entered for (audited as `content_source.credential_cleared`).
- **CA per source**: an optional PEM bundle (certificates only), added to the system roots for this source's fetches only.
- **SSRF guard.** Only https; the guarded transport resolves the host once and refuses loopback, link-local, metadata and private ranges at dial time. Private ranges are reachable only where the installation opened them (`OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS`) and the organization has the `content_sources.private_git` feature, decided **per connection at dial time** (the fetch's context carries the organization's decision; an organization without the feature reaches public addresses only, even where the installation allow-list has ranges, so a host rebinding to a private address is refused). Keep-alives are off for these fetches, so a connection opened for one organization is never reused for another. Cross-host redirects never carry the credential.

## Webhook

`POST /{id}/webhook` returns a secret once (only its SHA-256 is stored).
The repository calls `POST /hooks/content-sources/{id}` with the secret in
`X-OpenCTEM-Webhook-Token`, or as a GitLab webhook's secret token
(`X-Gitlab-Token`). The secret is compared in constant time; the body is
ignored; the call only queues a sync (at most one a minute, 60 accepted calls
an hour per source, plus per-IP and per-source request limits). Every refusal
(unknown source, wrong secret, webhook off, feature denied) is the same 401.
Setting a secret needs the `content_sources.webhook` feature.

## Test

`POST /test` (a new configuration) and `POST /{id}/test` (a saved source, with
optional overrides) run the real fetch, archive, lint and rule count and store
nothing. The stored credential is used only while the host is unchanged. At
most 10 calls an hour per source (or per organization for an unsaved one).

## Resource limits

Each fetch clones into the server's temporary directory, so the server bounds
them itself, whatever the organization's limits:

- **Concurrency.** At most 3 repository fetches run at once per API process,
  shared by Test and the sync worker. Test over the cap answers 503
  (`FETCH_BUSY`); the worker claims nothing until a slot is free and the due
  sources stay due.
- **Free disk.** Before cloning, the free space of the temporary directory
  must exceed the clone cap (200 MiB) plus 1 GiB; otherwise the fetch is
  refused (`SERVER_DISK_LOW`, 503 for Test, a failed sync otherwise). A free
  space that cannot be read refuses too. A full disk stops the database.
- **Storage.** A snapshot's bytes count inside the organization's 2 GiB pack
  quota (shared with uploads), and `content_storage_mb` caps them separately.

## Limits and features

Every limit and feature goes through the entitlement service ([limits](limits.md)):
`content_sources` (create), `content_storage_mb` and `content_snapshot_max_mb`
(sync; Test checks the per-item cap), the floor `content_sync_floor_minutes`
(saving a schedule), and the features `content_sources.webhook`,
`content_sources.review_policy` and `content_sources.private_git`. The core
sets no plan values: a key with no row is unlimited, which is every
self-hosted install by default. A hosted service caps organizations before its
control plane writes their rows through the instance's self-service default
limits (`SELF_SERVICE_START_LIMITS` or the console setting, see
[limits](limits.md)): the four keys are valid there and are copied to each new
self-service organization. The sync interval never goes below the
installation's floor of 5 minutes, whatever the limits say. `content_sources` counts only sources the platform fetches
(`mirror`, `proxy`), and the storage limits count only snapshots the platform
holds; the number of rules is never limited. A lowered limit refuses additions only: existing sources
are never deleted and keep their last promoted snapshot.

## API

`/api/v1/content-sources`, tenant from the token, gated by the Rule Sources
module (`template_sources`):

| Route | Permission |
|---|---|
| `GET /`, `GET /{id}`, `GET /{id}/snapshots`, `GET /{id}/snapshots/{snapshot_id}` | `scans:sources:read` |
| `POST /`, `PUT /{id}`, `PUT /{id}/credential`, `POST /{id}/webhook`, `POST /test`, `POST /{id}/test` | `scans:sources:write` + recent sign-in |
| `DELETE /{id}/credential`, `DELETE /{id}/webhook`, `POST /{id}/sync` | `scans:sources:write` |
| `DELETE /{id}` | `scans:sources:delete` + recent sign-in |
| `POST /{id}/snapshots/{snapshot_id}/approve`, `POST /{id}/rollback` | `scans:sources:approve` + recent sign-in |
| `POST /{id}/snapshots/{snapshot_id}/reject` | `scans:sources:approve` |

Errors: a refused sync or Test answers its code (`CONTENT_SOURCE_LINT_FAILED`,
`CONTENT_SOURCE_SECRETS_FOUND`, `CONTENT_SOURCE_FETCH_FAILED`, ...) with the
report; limits answer 403 `LIMIT_REACHED` or `FEATURE_NOT_INCLUDED`; too many
Test or webhook calls 429.

## Audit

`content_source.created`, `updated`, `deleted` (high), `credential_set`
(high), `credential_cleared`, `webhook_set`, `policy_changed` (high; a switch
to `auto` is high), `sync_requested`, `synced`, `sync_failed`, `promoted`
(high; automatic promotions too, and a four-eyes refusal as denied), `rejected`
and `rolled_back` (high).

## Threat model

| Threat | Control |
|---|---|
| SSRF through the URL | https only, guarded dial (resolve once, refuse blocked ranges), private ranges only where the installation opened them and the organization has the feature |
| Reading the server's disk through the repository | bare clone, files read from git objects only; symlinks and submodules skipped; local and `file://` URLs refused |
| Credential theft or misuse | sealed with the installation key and bound to source, organization and host; never returned; cleared on a host change; sent only over TLS to that host |
| Malicious upstream commit | candidate with diff; tier escalation, license change, mass removal and duplicate ids stop automatic promotion; tier escalation forces four-eyes review |
| Cross-organization access | tenant predicate on every statement; 404 for other organizations' and hidden sources; signing key from the source row; platform rows never written by an organization route |
| Webhook abuse | per-source secret, constant-time compare, no content accepted, rate limits, one answer for every refusal |
| Resource exhaustion | clone size cap, file and size limits, sync and lint timeouts, one sync per source at a time, limits per organization, at most 3 concurrent fetches per server process shared by Test and sync (Test answers 503 when full), no fetch when the clone disk would drop under 1 GiB free beyond the clone, snapshot bytes inside the 2 GiB pack quota, fair claim across organizations |

## Key files

- `api/migrations/*_content_sources.*`
- `api/pkg/domain/contentsource/` (source, snapshot, rules, repository)
- `api/internal/app/contentsource/` (service, sync, credential and webhook)
- `api/internal/infra/fetchers/git_snapshot.go`
- `api/internal/infra/postgres/content_source_repository.go`
- `api/internal/infra/http/handler/content_source_handler.go`, `routes/scanning.go`
- `api/internal/infra/controller/content_source_sync.go`
