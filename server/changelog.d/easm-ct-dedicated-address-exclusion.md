### Behaviour change: certificate-transparency names respect excluded dedicated addresses

- The CT sweep now skips an existing name that resolves to an excluded dedicated address. It is no longer promoted again and gets no CT evidence. The check uses the name's address properties or its `resolves_to` relations. Certificate SAN promotion and scan dispatch already followed this rule.
- Shared provider front ends never propagate, so names behind a CDN edge are still promoted.
- A failed address lookup promotes nothing for that run. Exposures are still written. No migration.
