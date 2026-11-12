# Asset domain membership

The findings filter `asset_domain=example.com` answers "every finding on
anything of example.com": the names, the addresses those names resolve to,
the services on those addresses, certificates for the names, web
applications and other assets with a DNS name. Matching on the asset's own
name alone misses most of them (a service is named `203.0.113.10:443:tcp`, a
certificate by its fingerprint), so which names an asset belongs to is
computed ahead of time and stored as keys.

## Keys

`asset_domain_memberships (tenant_id, asset_id, key)`, primary key
`(tenant_id, key, asset_id)`. An asset that belongs to the name
`api.example.com` has the keys:

- `api.example.com` (the name itself);
- `*.example.com` (every parent down to the registrable domain; a public
  suffix such as `com` or `com.vn` is never a key).

The filter value `example.com` matches the keys `example.com` and
`*.example.com` (the name and everything under it); `*.example.com` matches
`*.example.com` only (everything under it, not the name). It is one lookup on
the primary key, pinned to the caller's tenant
(`vulnerability.FindingFields`, field `asset_domain`).

## Membership rules

`pkg/domain/assetdomain` is the one place that decides membership. It reads
only evidence the platform already stores:

| Asset | Names it belongs to |
|---|---|
| domain, subdomain | its name |
| host (servers, compute, workstations, serverless) | its name when it is a DNS name, `hostname`, `fqdn` |
| certificate | `subject_cn` and `sans`; a wildcard `*.x` counts as `x` |
| service (ports, HTTP services, discovered URLs), application (websites, APIs) | the host of its name or URL (`url`, `base_url`, `host`, `hostname`) |
| database | the host of its name or `endpoint` |
| network (load balancers) | `dns_name` |
| ip_address (and a host or network named by an address) | the names with a `resolves_to` edge to it, unless it is shared (below) |
| anything with an `exposes` edge from, or a `runs_on` edge to, a host | also the host's names: a service on `203.0.113.10` belongs to the names that resolve to that address |
| repository, identity, container, kubernetes, cloud account, storage bucket | none: they have no network name |

An address is **never** a member when it is shared:

- a CDN or WAF edge, a SaaS hosting platform or a cloud provider's shared
  front end, by the edge address classifier (`pkg/domain/edgeaddr`: published
  ranges, the CDN the record names, the network holder);
- shared hosting: names of three or more registrable domains resolve to it.

Otherwise one organization's filter would list every other site behind the
same edge. Membership follows one host hop (name, address, service on the
address), never further.

At most 500 names count per asset (the first in sorted order) and 1,000
resolving names per address.

## Keeping it current

Every writer is covered without code in the writer:

- triggers on `assets` (insert; an update of the name, type, `deleted_at` or a
  property the rules read) and on `asset_relationships` (insert, delete, a
  change of either end or the type) put the asset, or both ends of the edge,
  in `asset_domain_queue` (one row per asset);
- the `asset-domain-membership` worker claims 500 queued assets at a time
  (`FOR UPDATE SKIP LOCKED`, so replicas can share the work) and rewrites the
  keys of each one and of the assets that read it, up to two edges out (the
  addresses a name resolves to and the services on them), in one transaction.
  More than 5,000 assets in one tenant's batch go back to the queue for the
  next batch, never dropped.

A change is visible to the filter after the next worker run (10 s by
default). A soft-deleted asset has no keys. The queue depth is the gauge
`openctem_asset_domain_queue_depth`.

## Security

- Every read of the worker is pinned to the queued asset's tenant on both
  sides of an edge; the schema also refuses an edge between two tenants'
  assets. A key row references its asset by `(tenant_id, asset_id)`.
- The filter value is checked and normalised before it is bound (lower case,
  no trailing dot, IDNA A-labels; addresses, URLs and bare public suffixes
  are refused) and is never part of the SQL text.
- The filter only narrows: the data scope, the pentest visibility rule and
  the hidden-asset rule apply to every list, count, group, export and saved
  view that uses it.
- Tests: `internal/infra/postgres/asset_domain_membership_db_test.go` (every
  kind, CDN and shared-hosting addresses excluded, name to address to
  service, cross-tenant, edge removal, rename, `*.x`, Unicode and upper
  case), `pkg/domain/assetdomain` (rules), and the registry walk
  `TestFindingTemplatesPinTenant`.

## Deploy

Migration `20261106125549_asset_domain_memberships` adds the two tables and
the triggers and queues every live asset once; the worker fills the keys in
the background. On a scratch database with 100,000 assets (two tenants,
20,000 edges) the backfill wrote 247,376 keys for 85,000 member assets in
about 21 seconds of worker time. Until it has drained, `asset_domain` returns
fewer findings than it will.
