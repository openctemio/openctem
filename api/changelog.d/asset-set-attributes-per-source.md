### Behaviour change: asset IP addresses, technologies and open ports are tracked per source

- Each source keeps its own record of every IP address, technology and open
  port it reported, with when it last saw it (RFC-069 §13). An element is
  removed from a source's contribution only when the same source observes the
  same coverage again without it: a port scan of the same port range on the
  same address, a DNS resolution of the same name. A partial scan no longer
  closes ports outside its range, and a top-N or default port scan closes
  only what an earlier scan with the same setting found.
- The asset shows the union of the trusted sources that reported within
  their TTL (the per-class source rules). Another source still reporting a
  port keeps it open; a source past its TTL stops counting on the daily
  re-resolution.
- Ingest no longer overwrites `ip_addresses` or unions `technologies`
  forever on existing assets, and no longer closes ports by "the same kind
  of scan".
- The asset timeline records added and removed elements with the source and
  scan run; a change that undoes the previous one within an hour folds into
  it. Re-sightings record nothing.
- Migration `asset_attribute_set_elements` adds the table (no backfill:
  existing values stay until a source that covers them reports).
