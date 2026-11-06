### Added: scan targets up to a /8, scanned live hosts first in /16 chunks

- One scan target may now name up to an IPv4 /8 (16,777,216 addresses) or an IPv6 /104, for example `10.0.0.0/8` or `172.16.0.0/12`. Before, the limit was a /16.
- Such a range is scanned live hosts first only: a host discovery pass sweeps it and only the hosts it finds go to the port and vulnerability stages. Saving one with "Every address" or "Inventory" is refused (`LARGE_RANGE_NEEDS_LIVENESS`).
- At each run the range is cut into /16 chunks, after removing the addresses no scope entry of the organization covers, the exclusions and the deny list. Nothing is stored or sent per address. Each chunk routes to the scan zone that holds it, and every sensor and job limit applies as before.
- New scan shows the address count, the chunk count and a rough duration, and asks for a confirmation before create.
- Scope policy setting "Widest range one scan target may name" (`max_range_prefix`, /8 to /24, default /8) lets an organization forbid wide sweeps.
- Design: `docs/rfcs/RFC-151-large-range-targets.md`.
