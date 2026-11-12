### Added: scan targets up to a /8, scanned live hosts first in /16 chunks

- One scan target may now name up to an IPv4 /8 (16,777,216 addresses) or an IPv6 /104, for example `10.0.0.0/8` or `172.16.0.0/12`. Before, the limit was a /16.
- Ranges wider than a /16 are opt-in: every organization, existing ones included, keeps a /16 limit until an approver raises the scope policy setting "Widest range one scan target may name" (`max_range_prefix`, /8 to /24, default /16). Raising it needs a recent sign-in, is audited at high severity and every administrator is told.
- Such a range is scanned live hosts first only: a host discovery pass sweeps it and only the hosts it finds go to the port and vulnerability stages. Saving one with "Every address" or "Inventory" is refused (`LARGE_RANGE_NEEDS_LIVENESS`), and so is a single-scanner scan or a workflow without a host discovery step (`LIVENESS_NEEDS_HOST_DISCOVERY`).
- The API requires `confirm_large_range: true` to create, edit or import (`?confirm_large_range=true`) a scan whose targets hold such a range; without it the request is refused with `LARGE_RANGE_UNCONFIRMED` and the address and chunk counts. New scan sends it after its confirmation.
- At each run the range is cut into /16 chunks, after removing the addresses no scope entry of the organization covers, the exclusions and the deny list. Nothing is stored or sent per address. Each chunk routes to the scan zone that holds it, and every sensor and job limit applies as before.
- New scan shows the address count, the chunk count and a rough duration, and asks for a confirmation before create; it reads the organization's limit to explain a range that is too wide.
- An asset group member network wider than a /16 is bounded and cut like a typed range.
- A range that holds private, link-local or loopback addresses anywhere (for example `172.0.0.0/8`, which holds `172.16.0.0/12`) now counts as internal and is scanned only inside a scan zone; before, only its first address was checked.
- Design: `docs/rfcs/RFC-151-large-range-targets.md`.
