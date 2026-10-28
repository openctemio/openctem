### Security: an immediate organization deletion now fails closed when its audit row cannot be written

- `POST /api/v1/admin/tenants/{tenantId}/purge` wrote its admin audit row only after the irreversible delete, and only logged a failed write, so an audit outage could erase an organization with no admin audit trail. The `organization.purge_requested` row (critical, with the reason) is now written first; when it cannot be written the request answers 503, nothing is deleted or locked out, and the second approval is handed back. The outcome row `organization.purged` follows the deletion.
