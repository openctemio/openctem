### Added: data freshness on the asset page, a stale filter and the enrichment switch

- Asset detail (sheet and page) shows **Data freshness**: per attribute
  class (DNS records, domain registration, network owner, web service, TLS
  certificate, open ports) its state (live, stale, dead, never observed),
  the tool that last saw it, its freshness window, and the asset's automatic
  enrichment with a link to its run (RFC-075).
- Inventory > Signals: **Stale data** and **Never enriched** filters
  (`?freshness=stale|never`, deep-linkable).
- Attack surface > Monitoring: **Automatic enrichment** switch.
- All new text in English and Vietnamese.
