### Security: a dangling DNS name is no longer resolved when someone else starts answering for it

- The EASM DNS check used to resolve an open `dangling_cname` (and a confirmed `subdomain_takeover`) as soon as
  the missing CNAME target existed again, which is exactly what a successful takeover looks like. It now resolves
  only when the name points into the organization (its own domain or a confirmed root, or confirmed addresses
  outside provider space, or no record at all). A name that answers from a new third party raises a suspected
  `subdomain_takeover` (high) that only a person resolves.

### Added: dangling names hosted by a provider, and dangling names stay in inventory

- Names that point at a provider which no longer serves them (its "not configured" page, or certificate
  trouble on the name while the CNAME still points at the provider) now raise `dangling_cname` with a response
  class and evidence (CNAME chain, provider, claimability, TLS state). A takeover template match on such a name
  is confirmed without an earlier DNS-only record.
- New provider list entry: LadiPage.
- Assets with an open dangling or takeover exposure are never demoted to stale by the lifecycle worker, and
  carry the tag `dangling_cname` while the exposure is open. No migration.
