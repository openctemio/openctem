### Added: platform setting for an organization's own mail relay (off, verified sender, on)

- An organization's e-mail notification channel can now carry the organization's own mail (invitations, account setup, member notices, scheduled reports) when "Also send my organization's own mail through this server" is ticked. This path was wired but never active, because it read other metadata keys than the integration service stores; it now reads the stored shape (settings from the metadata, the login from the encrypted credentials) and supports implicit TLS (port 465).
- New platform setting `email.tenant_relay` (console API `/admin/settings/email-relay`, env default `ORG_EMAIL_RELAY_MODE`): `off`, `verified_sender` (the sender address must be on a DNS-verified domain of the organization) or `on`. Defaults: `on` on a self-managed install, `verified_sender` with `MANAGED_SERVICE=true`. Changes need a super admin, a fresh step-up and a reason, and are audited as critical.
- Account security mail (verification, password reset, MFA and sign-in notices) always goes through the platform relay. A relay that cannot be used makes invitations and account setup mail fall back to the platform relay; scheduled reports are not sent.
- **Behaviour change:** channels saved before this change have the flag off, so nothing changes until an admin ticks it. New channels have it on.
- No migration.
