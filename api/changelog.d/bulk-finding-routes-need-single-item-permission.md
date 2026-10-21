### Security: bulk status and bulk assign now need the single-item permission too

- `POST /api/v1/findings/bulk/status` requires `findings:status` and `POST /api/v1/findings/bulk/assign` requires `findings:assign`, in addition to `findings:bulk_update`. Before, a custom role with `findings:bulk_update` alone could change statuses and assignees in bulk although the single-finding routes refused it.
- **Upgrade note:** built-in roles hold all three permissions and are unaffected. A custom role that relied on `findings:bulk_update` alone must be granted `findings:status` and `findings:assign`.
