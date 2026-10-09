### Added: team memberships with an end date

- A team (access group) membership can end on a date (`expires_at` and
  `expiry_reason` on `POST /api/v1/groups/{groupId}/members`, and
  `PATCH /api/v1/groups/{groupId}/members/{userId}/access` to set, move or
  clear it; at most 365 days ahead; `team:groups:members` with the usual
  delegation cap). Teams of type `external` (engagements, audits) require an
  end date for every member but their creator.
- Within a minute of the end date the membership is removed (controller
  `team-membership-expiry`), the member's data scope is recomputed, the
  removal is audited (`member.removed`, reason `expired`) and the member is
  told (migration 001431, RFC-050 W22).
