### Added: GET /api/v1/query/values completes search box values with counts

- The most frequent values (up to 20) of one field, with their counts, under the search box filter (`fq`) minus that field's own conditions, for value completion and facets. Counts run through the same plan as the list, so the tenant, the caller's data scope, the pentest member rule and the server-side exclusions apply; fields the caller may not use are unknown.
- A 1 second budget: past it the answer has no counts (enum and boolean values are still listed). Answers are cached per caller for 60 seconds. Rate limited per user (burst 20, 2 per second) and bounded by the custom query concurrency caps.
