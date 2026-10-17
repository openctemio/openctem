### Changed: neutral wording for modules that are not available

- `MODULE_NOT_ENABLED` now says "This module is not available for this organization" (and "...no longer available for this organization: it is read-only for now" during the grace). The `reason` codes are unchanged. The unavailable-entitlement 503 no longer mentions a plan.
- Enabling a module that is not available is refused with "is not available for this organization".
- The AI triage token-budget error now asks the person to contact their administrator.
- Platform scanning, when not allowed, says "Platform scanning is not available on this installation".

### Removed: inert plan checks

- The unwired single-sign-on plan check on trusted organizations (`ErrPlanLacksSSO`) and the AI triage plan checks that always allowed. Nothing was enforced by them.
- The `make assign-plan` and `make list-plans` targets (they used tables that no longer exist); `make list-tenants` lists organizations only.
