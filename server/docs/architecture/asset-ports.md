# Open ports of assets

`asset_ports` lists, for every asset, the open ports it answers on, so the
asset list can filter by port and service with one index lookup and show an
Open ports column without walking edges per row.

## Where the rows come from

A port scan stores each open port as a service asset with sub type
`open_port` (properties `port`, `transport` or `protocol`, `service` or
`name`) that its address exposes (`ip_address -exposes-> service`). From
those facts an asset answers on a port when it is:

- the `open_port` service itself;
- the address (or host) that exposes it;
- a name that resolves to that address (`resolves_to`, one hop).

Only live, active open ports with a port number from 0 to 65535 count.
Transport is `tcp`, `udp`, `sctp` or empty; the service name is lower case,
at most 64 characters. The rows are derived data: they never hold anything
the assets and edges do not.

## How they stay current

AFTER triggers queue an asset in `asset_port_queue` when:

- a service asset is created;
- a service, address or host changes type, sub type, status, deletion or
  one of the port properties;
- an `exposes` or `resolves_to` edge is created, changed or deleted (both
  ends).

The `asset-ports` controller drains the queue every 10 s in batches of 500
(`FOR UPDATE SKIP LOCKED`, so replicas can run side by side). For each
claimed asset it rewrites the rows of the asset, of the addresses that
expose it and of the names that resolve to any of those, in chunks of 2,000
assets. Metrics: `openctem_asset_ports_queue_depth`,
`openctem_asset_ports_refreshed_total`. The migration queues every live
service asset once, so the worker fills the table after deploy.

## Isolation

Both tables carry `tenant_id` with composite foreign keys to
`assets (tenant_id, id)` for the asset and the port asset (`ON DELETE
CASCADE`), so a row can never pair assets of two tenants. Every statement of
the worker is pinned to one tenant. Reads join the table on the caller's
tenant and go through the caller's data scope like every list filter. An
asset merge drops the merged assets' rows and queue entries and queues the
kept asset (`asset_merge_plan.go`).
