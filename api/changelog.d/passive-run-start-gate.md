### Fixed: passive scans no longer skip discovered names as "ownership not confirmed"

- A scan run whose every probe is passive (passive intensity, a passive scanner, or a workflow of passive steps) now gates its targets with the passive gate at run start. Names a scan discovered and nobody confirmed yet, and names that resolve only through a wildcard DNS record, are looked up again; rejected names, scope exclusions, the deny list and names outside the organization's scope are still refused.
- A target refused because its name resolves only through a wildcard DNS record is reported as its own skip reason (`wildcard_only`, informational) instead of "Ownership not confirmed".
- A registrable domain (`example.com`) is never marked wildcard-only, and an existing mark on one is ignored: a wildcard record never answers for the domain it sits under.
- The "Ownership not confirmed" group now reads "Discovered, not confirmed as yours" and says how to fix it.
