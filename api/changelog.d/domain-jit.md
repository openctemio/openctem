### Security: per-domain just-in-time provisioning and lapsed-domain handling

- **Per-domain JIT:** each verified SSO domain of an organization has its own just-in-time provisioning.
  - `jit_enabled` turns provisioning on or off for the domain.
  - `jit_role` is `viewer`, `member`, or empty for the identity provider default. Administrators are never provisioned.
  - Set with `PATCH /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}` (platform administrators).
- **Lapsed domains:** a domain whose DNS proof lapsed stops provisioning, and its members are flagged with `domain_lapsed` in the members list.
- **Password reset:** a forgot-password request for an address on a lapsed domain that no organization holds now mails no reset link.

Upgrade: migration 001326 adds two columns to `verified_domains`. Existing domains keep provisioning as before.
