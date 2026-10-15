### Fixed: the sidebar organization card shows the organization's real plan

- The membership list (`GET /api/v1/users/me/tenants`, the session bootstrap) and `GET /api/v1/tenants/{id}` reported every organization as "free" from a leftover placeholder, while Settings > Plan & usage, the console and limit enforcement read the stored plan. All of them now read `tenant_plans`; an organization with no stored plan (the one bootstrap-admin creates, one created in the console or from an approved access request, one older than plans) is Enterprise everywhere, as it already was for limits.
- A self-service organization's Free plan is now stored in the same transaction as the organization. Before, a failed write after the organization existed left it with no plan, and so without the Free limits.
- A plan change in the console is audited with the plan it replaced (`from`).
- No data change: limits were already enforced from `tenant_plans`, so no organization's limits change.
