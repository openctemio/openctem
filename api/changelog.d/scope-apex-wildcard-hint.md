### Changed: a refused apex explains that a wildcard covers subdomains only

- Scanning `example.com` when only `*.example.com` is in Scoping > Targets was refused with a generic "matches no scope target". The reason now says the wildcard covers subdomains only and to add the apex itself. The matching rule is unchanged (a wildcard never matches the apex), and the message names only the caller's own scope entries.
- Scoping > Targets: adding a domain wildcard offers an unchecked "Also include the apex" option that creates both entries, and wildcard domain targets show a "subdomains only" badge.
