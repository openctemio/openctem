### Security: exposure stats follow the caller's data scope

- `GET /api/v1/exposures/stats` counts only the exposures the caller may list. A restricted member used to see tenant-wide totals, severities and mean time to resolve above a list narrowed to their scope; the numbers now come from the list's own filter (tenant, data scope, deleted assets excluded), so they always match.
- The response now includes `by_event_type`, which the Exposures analytics "By event type" card reads; it was always empty before.
- Mean time to resolve no longer counts exposures of deleted assets.
