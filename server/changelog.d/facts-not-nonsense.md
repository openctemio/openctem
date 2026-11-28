### Fixed: pages no longer state malformed or meaningless values as facts

- Attack surface review: an address range item is suggested as a range rule (its own range, or its /24 or /48), never as a domain wildcard ("*.0.113.0/24" for 203.0.113.0/24); a name that is not a host name (an app id with its platform, an address with a mask) gives no domain wildcard ("*.20.1.0", "*.example.holdings.shop (android)").
- EPSS: when the feed has no percentile for a score, the percentile is unknown, not 0. Findings, exposures and the threat intel lookup no longer say "97.6%, 0th percentile"; the next priority pass clears the stored 0. The threat intel EPSS answer omits `percentile` when it is unknown.
- Compliance: a framework with no control assessed says "Not assessed yet" instead of "0% compliant"; the card's labels are translated.
- Validation overview: "Validated top-priority fixes" says "None yet" when no top-priority finding is closed, instead of a bare dash.
- Exploration: the version check question reads "Is the version that matched a critical vulnerability really running?".
- Metric strips: a status inside a figure tile keeps normal letter spacing, so its words no longer run together ("Allanswering", "Noneconnected" on the console overview).
- Docs: server/docs/architecture/exploration.md (version check question).
