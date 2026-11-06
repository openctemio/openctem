### Changed: version matches on a provider's shared hosting are attributed to the provider

- A version-based match on a host that a provider's shared front end serves (CDN or WAF edges, SaaS and
  site-builder hosting, including an address that the organization's names reach only through such a provider)
  now records `hosted_by` and `attributed_to: provider` and is capped at priority P3: it is context on the
  organization's name, not its own critical vulnerability. Matches on the organization's own addresses are
  unchanged.
- The edge labels' dataset knows LadiPage (`ladipage.com`, SaaS hosting).
- Regression tests pin that a CVE with no version range for the product, and a distribution build, are never
  raised by default.
