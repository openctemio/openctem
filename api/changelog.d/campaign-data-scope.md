### Security: restricted members no longer see campaign details outside their data scope

- A member restricted by data scope reading a remediation campaign (`GET /api/v1/remediation/campaigns` and `/{id}`) no longer sees the explicit finding ids or the asset id of its filter that are outside their scope, nor the organization-wide risk fields. Counts were already scoped.
- The remediation key side table is joined to findings of the same tenant only (defence in depth).
