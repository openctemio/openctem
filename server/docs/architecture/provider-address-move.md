# Provider shared addresses: the one-time move

An address inside a range a provider publishes for infrastructure many
organizations share (a CDN edge, a shared mail or web front end) is recorded
on the name that resolves to it, with first and last seen, not as an address
asset of the organization. Addresses a scan reports results on are still
recorded. The organization's asset is the name: its records, its certificate
and its services. The provider's addresses rotate every day and belong to
everyone who uses the provider.

Before this change, every address a name resolved to became an `ip_address`
asset with a `resolves_to` edge from the name. The `provider-addresses`
operator command cleans up what that left behind: it folds the existing
name-to-address links into the names' address history and archives the
provider addresses that carry nothing else. It is a one-time job per
organization. It ships off: nothing in the server starts it, and an operator
runs a dry run first. The runbook is
[operations/provider-address-move.md](../operations/provider-address-move.md).

Status: shipped (the command, its journal and restore, and the revive on a
direct result). The scope card that lists scope entries inside shared ranges
and the console's "Addresses" block on a name are separate changes.

## What counts as a provider shared address

Only a published range decides: `edgeaddr.Default().SharedFrontEnd(address)`
(class edge, SaaS hosting or cloud shared, range basis, and no dedicated
prefix of the dataset holds it). A network holder's name, a CDN header or a
host-name suffix never decides. An address no range holds is treated as
possibly the organization's (fail closed) and is never touched. Classification
runs in Go over the batch, never as a SQL join against the prefix list.

## What the move does, per address

The command walks the organization's `ip_address` assets in batches of 500 by
id; a batch ends early once it holds 150 provider addresses, because their
writes (not the reads) set a batch's time. For each one inside a shared
range:

1. **Fold.** Every `resolves_to` edge from a name to the address becomes an
   `ip_addresses` set element on the name, source kind `scan`, source name
   `migrated_resolves_to`: first seen is the edge's `created_at`, last seen is
   `COALESCE(last_verified, created_at)`, and `removed_at = last_seen`. The
   folded rows are history only: the name's current addresses come from the
   real sources (the DNS resolver), which already hold them. The fold has its
   own upsert that keeps the earliest first seen and the latest last seen; it
   never moves `last_seen` backwards and never touches another source's row.
2. **Relink.** An `exposes` edge from the address to a service whose host
   part is a domain or subdomain asset of the same organization
   (`https://app.example.com`, `app.example.com:443`) is replaced by an
   `exposes` edge from that name (discovery `inferred`, description "moved
   from a provider address"). A `serves_certificate` edge moves to every
   name that resolved to the address, or names a moved service, that the
   certificate covers (exact or one-label wildcard). Findings are not
   touched: they stay on their service with their status, SLA and fingerprint.
3. **Decide.** One bucket per address, in this order:

   | Bucket | Meaning | Result |
   |---|---|---|
   | `active_run` | a target of a queued or running scan run | skipped this pass (journal outcome `skipped_active_run`) |
   | `person` | a person decided its attribution, or set its status by hand | kept; status and attribution untouched |
   | `entry` | a scope entry for exactly that address, or a CIDR or range wholly inside a shared range | kept |
   | `reference` | a tag, a child asset, or any reference of the asset merge list other than history | kept |
   | `manual_edge` | a person drew an edge to or from it | kept; that edge untouched |
   | `revived` | a direct result revived it after an earlier pass | kept |
   | `address_services` | services named by the address itself (`addr:993:tcp`) | kept; the services and findings stay |
   | `other_edges` | an edge the move does not move (a certificate that covers no name, a service named by a host that is not an asset) | kept |
   | `plain_after_relink` | only name services, now moved | archived |
   | `plain` | nothing but name-to-address links | archived |

   Archived: status `archived` (a status history row with reason
   `provider_address`) and attribution `dependency` /
   `provider_shared_front_end`. Kept: status unchanged; a `discovered`
   attribution becomes `dependency` / `provider_shared_front_end`; any other
   attribution stays. A person's decision (`decided_by` or `decided_at`) is
   never overwritten. In both cases the `resolves_to` edges are deleted after
   the fold, so no name points at a provider address any more.

"History" references, which do not hold an address, are the change events,
attribute sources, set elements and freshness, enrichment requests, risk and
priority queues, identifiers, discovery evidence, coverage, liveness, scan
step outputs, scan run targets and runs, group membership history, exposure
events and the derived access cache (`providerHistoryRefs` in
`internal/infra/postgres/provider_address_move_repository.go`). Every other
reference in `asset_merge_plan.go` keeps the address, so a new table there is
safe by default.

The command never writes `scope_targets` or `scope_exclusions`. Scope
entries inside shared ranges are counted for the scope card, which decides
them with the organization.

## Journal

`provider_address_moves` (migration `20261119023455`) has one row per run of
one organization: mode `dry_run`, `apply` or `restore`, state, counts, the
job version and the dataset version it classified with, the resume cursor,
the actor and the one-time notice. At most one apply or restore runs per
organization (a partial unique index); a second runner resumes it.

`provider_address_move_items` has one row per address an apply changed or
skipped: bucket, action (`archive`, `keep`, `skip`), prior status, prior and
new attribution, the full rows of every edge deleted (`edges`) and added
(`added_edges`), the folded history rows (`folded_keys`), and the outcome
(`applied`, `skipped_active_run`, `restored`, `changed`, `revived`,
`reclassified`). `asset_id` has no foreign key: the journal outlives the asset
and is listed in `assetMergeLeftAlone`. Both tables are tenant-scoped (keys,
row-level policies in shadow mode, `ON DELETE CASCADE` from tenants) and in
the tenant table list.

## Runs and safety

- **Dry run (default).** Each batch is a read-only, repeatable-read
  transaction. The plan is computed by `provideraddr.PlanBatch` from what the
  batch read; a dry run carries what earlier batches planned in memory, so
  its counts equal the apply's (tested). It writes one `dry_run` row with the
  counts.
- **Apply.** Each batch is one repeatable-read transaction:
  `pg_try_advisory_xact_lock` on the organization (another runner gets "busy",
  a dry run takes the shared form), `lock_timeout` 2 s,
  `statement_timeout` 30 s, the run's cursor read under `FOR UPDATE`, the
  writes, and the new cursor and counts, committed together. A lock wait, a
  time limit or a serialization conflict rolls the batch back and it is
  retried; an interrupted apply resumes after the last committed batch. The
  status of every finding the batch could reach is compared before and after
  its writes in the same snapshot: any difference rolls the batch back and
  marks the run failed. A second apply finds nothing to change and journals
  nothing new.
- **Keyed by dataset version.** A run records the dataset version it
  classified with. A dataset that newly lists a range makes the next pass move
  the addresses it now holds (A3). A dataset that withdraws a range makes the
  next pass restore the items whose address is no longer shared (outcome
  `reclassified`): a `confirmed` attribution comes back as `discovered`, so
  the move never confirms an address (A4).
- **Close.** One audit entry per organization (`asset.provider_addresses_moved`,
  counts in the metadata), one dashboard rebuild request, and the one-time
  notice: an in-app notification to the organization and the English and
  Vietnamese text on the run row for the console. Archiving also marks the
  dashboard facts dirty through the existing asset triggers.
- **Restore.** `-restore` walks the organization's applied items: when the
  address still has the status and attribution the move gave it, the prior
  status and attribution come back, the deleted edges are re-inserted with
  their ids, and the added edges and folded rows are removed (outcome
  `restored`); otherwise the item is left as is with outcome `changed`.
- **Revive.** When a scan reports a result on an address the move archived
  (an applied archive item exists), ingest makes it active again (still
  `dependency`) and records outcome `revived`. An address a person archived has
  no such item and stays archived.

## Threat model

- **Who can run it.** Only someone with shell access to the API container or
  host and the database credentials: it is an operator command linked to the
  server binary, with no HTTP route. `-apply` and `-restore` need one
  `-tenant`. Every change leaves an audit entry in that organization.
- **Tenant isolation.** The organization id comes from the command line and is
  bound into every statement; rows read are never used to pick a tenant. Two
  organizations with the same names and addresses are tested side by side.
  The report prints counts only, never names or addresses.
- **No silent loss.** Every edge deleted is journaled in full, history is
  folded before an edge is deleted, addresses are archived, never deleted, and
  findings are never written.
- **Fail closed.** An address no published range holds is never touched. A
  person's decision, a scope entry or any reference keeps an address.
- **Load.** Batches are short transactions with bounded lock waits, so
  ingest never waits on the move for more than 2 seconds.

## Key files

- `pkg/domain/provideraddr`: buckets, the plan (`PlanBatch`), scope entry
  coverage, the notice text.
- `internal/infra/postgres/provider_address_move_repository.go`: batches,
  journal, restore, revive.
- `internal/app/provideraddr`: the runner (dry run, apply, restore, close) and
  the plain-text report.
- `internal/tools/provideraddrcmd`: the `provider-addresses` command.
- `internal/app/ingest/provider_revive.go`: revive on a direct result.
- `migrations/20261119023455_provider_address_moves.*.sql`: the journal.
