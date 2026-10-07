### Security: path- and method-aware scope exclusions with a testing mode

- A `path` exclusion is now a web rule: a host pattern, a segment-aware path prefix and the methods it blocks
  (migration 001198 migrates existing `path` rows, for example `/api/v1/*` to host `*` + prefix `/api/v1`; two old
  rows that read as the same rule are merged into the one in effect).
- It is enforced at dispatch (URL targets under it are excluded), in the job (`web_scope.deny_paths`, or GET/HEAD only
  for a method-scoped rule) and at ingest (endpoints under it are recorded excluded-untested with the exclusion).
  A path rule never excludes a whole host.
- `PUT /api/v1/scope/exclusions/{id}/testing` sets `blocked`, `read_only` (GET, HEAD) or `allowed` with an optional
  deadline (at most 90 days): exclusion approval permission and step-up, audited, administrators notified. It never
  widens scope beyond the organization's own in-scope assets. Design: RFC-056, contract in RFC-054 §6.2.
- **Upgrade note:** a web step whose sensor does not support `web_scope` fails when a path exclusion applies to its
  host; update the sensor.
