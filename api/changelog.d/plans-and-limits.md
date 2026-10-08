### Added: plans and limits for organizations

- Organizations are on a plan (Free, Pro, Enterprise) that caps members, assets, sensors, API keys, CI trusts and invitations a day. Platform administrators edit the plan defaults in Console > System > Plans (super admin, fresh authenticator code, audited critical, other administrators emailed) and set per-organization overrides with a reason and an optional expiry (ops_admin+, audited).
- Lowering a limit never removes anything; new additions over it are refused with 403 `PLAN_LIMIT` and the organization is flagged over limit. Refusals are counted in `openctem_plan_limit_refusals_total`.
- A self-service organization starts on Free; one person owns at most one Free organization by default. Organizations created before this change are Enterprise (no limits). Migration 001325 (two new, empty tables).
- Organization owners and admins see the plan and usage at `GET /api/v1/tenants/{tenant}/plan`.
