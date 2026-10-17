### Behaviour change: per-organization limits replace plans

- The core no longer has plans. An organization is unlimited and may use every module unless the instance operator (or, on a hosted service, its control plane) set a limit or a module deny for that organization. A self-hosted install with default settings has no limits anywhere.
- New organizations created by a person themselves start with the instance's **self-service default limits** (Console > System > Limits, `GET/PUT /api/v1/admin/settings/limits`, super admin with a fresh authenticator code). Empty by default. The same setting holds `orgs_per_user`, the per-person cap on self-service organizations (unlimited by default). The limits are written in the transaction that creates the organization.
- Migration 002890 (`per_organization_limits`) keeps every organization's caps: the limits of its plan become operator limits with the reason "migrated from plan", and modules its plan left out become module denies. Plans, plan defaults and the plan to module map are dropped.
- Over a limit only new additions are refused; nothing is deleted. A denied module keeps read access for 30 days.
- **Self-service sign-up requires starting limits.** With sign-up in `self_service` (`SIGNUP_MODE=open` or the console policy), the API refuses to start and the console refuses to switch to self-service until starting limits are configured: a saved console setting, `SELF_SERVICE_START_LIMITS` (a JSON object of limits, or `unlimited`), or the internal entitlements API.

### Removed: plan endpoints and fields

- `GET/PUT /api/v1/admin/settings/plans`, `GET/PUT /api/v1/admin/settings/plan-modules`, `GET/PUT /api/v1/admin/tenants/{tenantId}/plan`, `PUT/DELETE .../plan/overrides/{key}`, `PUT/DELETE .../modules/{module_id}/grant` and `GET /api/v1/organization/plan`.
- The `plan` field of `GET /api/v1/users/me/tenants` (and the session bootstrap) and of `GET /api/v1/tenants/{id}`, and the `plan` column and filter of `GET /api/v1/admin/tenants` (each row now has `limits_apply`).
- Replaced by `GET /api/v1/organization/limits` (owners and admins: the limits that apply, usage and unavailable modules; `applies: false` when nothing applies), `GET/PUT/DELETE /api/v1/admin/tenants/{tenantId}/limits[/{key}]` and `PUT/DELETE /api/v1/admin/tenants/{tenantId}/modules/{module_id}/deny`.
- The error code of an addition over a limit is now `LIMIT_REACHED` (was `PLAN_LIMIT`), and the metric `openctem_plan_limit_refusals_total` is now `openctem_limit_refusals_total`.
- **Upgrade note:** an installation running self-service sign-up must set `SELF_SERVICE_START_LIMITS` (for example `unlimited`) or save limits in the console before upgrading, or the API will not start. Stop the API while migration 002890 runs (it renames and drops tables). API clients that read `plan` or call the plan endpoints must move to the limits endpoints.
