### Changed: emerging threats page is a triage queue

- Prioritization > Emerging threats now reads as a triage queue: levels are shown as Act now, This week and Watch (the API values immediate, digest and listed are unchanged), the summary has five filter tiles (Act now, Untriaged, This week, Known exploited, Internet-facing), filters sit in one toolbar with a filter panel, rows are compact, and a row opens a drawer with the score breakdown, affected product versions, crown jewels and every action, including scanning the affected assets.
- `GET /api/v1/emerging-threats` adds `product`, `product_count`, `critical_assets` and `ets_breakdown` to each row, `new` to the summary, and the `kev=true` filter. Product and counts are computed over the caller's in-scope assets only.
