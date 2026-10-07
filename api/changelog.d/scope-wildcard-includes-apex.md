### Behaviour change: `*.example.com` in scope now covers `example.com` too

- A domain scope target or exclusion `*.x` (and `**.x`) now covers `x` itself
  as well as every name below it (RFC-054 §4.1). Scanning `example.com` with
  only `*.example.com` in Scoping is no longer refused. An exact `x` still
  covers only `x`.
- To keep the subdomains in scope without the apex, add an exclusion of exactly
  `x`; the exclusion carves out the apex and nothing else.
- Exclusions use the same matcher: an exclusion `*.x` now also excludes `x`.
- **Upgrade note:** existing `*.x` scope targets start covering their apex on
  deploy (live had 3 wildcard targets, one without its own apex entry). Review
  them in Scoping › Targets and add an apex exclusion where the apex is not
  yours.
