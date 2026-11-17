### Security: search suggestions follow a removed access at once

- Value completion in the search boxes (`GET /api/v1/query/values`) kept each answer for 60 seconds per user, so for up to a minute after a person lost a group, a grant, a campaign or a role, repeating the same request returned values and counts from their former access. Answers are no longer kept between requests: every call runs as the caller with their current access. The 1 s budget and the per-user, per-organization and per-process limits bound the cost.
- Docs: server/docs/architecture/query-language.md
