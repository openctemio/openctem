### Security: least-privilege defaults for every way into an organization

- **Behaviour change, SCIM:**
  - a person provisioned by SCIM is now a viewer (was member);
  - a group change applies only a matching role group. Without one the role is kept, and an administrator falls back to member. Previously anyone without a role group became a member.
  - To keep giving SCIM users the member role, map an identity-provider group to member.
- **Defaults:**
  - the invite and add-user dialogs preselect the viewer role;
  - a new SAML configuration's default role is viewer.
- **Approval mode:** `PATCH /tenants/{tenant}/settings/security` takes `jit_requires_approval` (owner, step-up).
  - People the organization's SSO admits for the first time wait, with no access, until an administrator approves them in Members.
  - Approving re-enables the member; rejecting offboards them.
- **Domain JIT raises need an owner:** a platform administrator who raises a domain's just-in-time provisioning (admits new people, or gives them a higher role) now waits for an owner's approval, like other SSO changes. Lowering it applies at once.
- **Privilege notices:** owners and administrators are told when a member's role is raised, when someone gets the admin, owner or a full-data-access role, and when a newcomer is approved.

Upgrade: migration 001331 widens the SSO change kinds.
