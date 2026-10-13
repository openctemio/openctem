### Fixed: names in a private DNS zone are not internet-facing

- A domain or subdomain reported with `zone_visibility: private` (the cloud DNS collector sends the visibility of the zone each name is in) is created with exposure `private` and not internet-accessible, instead of the public default of a DNS name, and its exposure claim for attribute reconciliation is `private` (a person's decision still wins on an existing asset).
- A root domain that only private-zone names of a report name is created `private`; a root that a public-zone name also names stays public.
