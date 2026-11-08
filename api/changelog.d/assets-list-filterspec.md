### Added: the asset inventory on the list query contract

- `GET /assets` reads its filter through the `assets` field registry (`pkg/domain/assetlist`), like the findings list: every filter is a registry field, compiled as the caller with the tenant and data scope first. New: `POST /assets/search` takes a FilterDocument (OR groups, NOT, long lists), saved views for the assets page (`GET /assets?view=<id>`, migration `20261108184839`), the search box (`entity=assets` on `/query/parse`, `/query/values`, `/query/schema`) knows every inventory filter, `name` takes patterns (`api-*`), and new fields `domain` (domain membership), `tag_all`, `finding_count`, `technology=name@version`.
- Counts stop at 10,000: `total` is exact up to 10,000, above it `total_capped` is true. `cursor` (empty for the first page) pages in last seen order with `next_cursor`, without the 10,000 offset limit.
- List and count statements run read-only under a 5 s statement timeout (503 `QUERY_TIMEOUT`).

### Deprecated: old GET /assets filter params

- `types`, `lenses`, `criticalities`, `statuses`, `scopes`, `exposures`, `tags`, `exclude_tags`, `search`, `min_risk_score`, `max_risk_score`, `is_crown_jewel`, `business_unit_ids`, `asset_group_ids`, `owner_ids`, `ids`, `in_cidr`, `data_classifications`, `is_control_plane`, `environments`, `providers`, `last_seen_after`, `last_seen_before`, `expires_after`, `expires_before`, `min_confidence`, `max_confidence`, `first_seen_after`, `first_seen_before`, `tags_mode` and `technology_version` next to `technology` keep working and answer with `Deprecation`, `Sunset` (2026-12-20) and a `Warning` naming the new param. They are removed two releases later.

### Behaviour change: GET /assets refuses unknown params and bad values

- An unknown param or an enum value the field does not take is `400 INVALID_FILTER` (it used to be ignored), so a typo never widens a list. The value is never echoed.
- `name=x` is now the exact name or a pattern (`*x*`); `name_contains=x` is the old partial match.
- A user-less API key matches the system tags of private bug-bounty programs it is not a member of no more (owners and program members still do).
