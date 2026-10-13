### Changed: network ranges are scanned in /24 pieces, chunked by address count

- The scan target gate cuts every range target into pieces of at most /24
  (IPv6 /120): a /16 is 256 pieces, recorded one run-target row each, never
  one per address (RFC-088).
- A port-scan step closes a chunk before it would reach more than 1 024
  addresses (a range piece weighs its address count, any other target 1),
  so a /16 is 64 chunks that every eligible sensor shares instead of one
  command on one sensor for hours. Other capabilities keep their target
  counts.
- Politeness knows about overlap: a chunk holding a range and a chunk
  holding an address inside it are never run at the same time by two
  sensors, in either order, by poll, by id or in a batch claim; two
  addresses of one /24 still run in parallel. Host keys stay per tenant.
- No migration and no operator step. Chunks already queued keep their old
  keys (a range string is its own key) until they finish.
