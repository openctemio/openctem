### Security: removing a member always needs a recent sign-in

- `DELETE /api/v1/tenants/{tenant}/members/{id}` ran the same offboarding as
  `POST /api/v1/organization/members/{id}/offboard` but without step-up, so a
  stolen administrator session could strip a member's access without
  re-authenticating. The DELETE route is removed; offboarding has one route,
  which requires step-up. The web console already used it.
- A new test maps every step-up service action to each user-plane route that
  reaches it and fails when one of them lacks step-up.
- **Upgrade note:** API clients that called the DELETE route use
  `POST /api/v1/organization/members/{id}/offboard` (empty body when the
  member owns nothing, otherwise a reassignment plan). The DELETE answers 405.
