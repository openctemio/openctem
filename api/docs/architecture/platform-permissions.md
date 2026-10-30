# Platform permission reference

Generated from `pkg/domain/platformauthz` and `adminRoutePermissions`
(`internal/infra/http/routes/admin_permissions.go`) by `make -C api platform-authz-docs`;
do not edit by hand. Design: RFC-134. These permissions exist only on the
console; the tenant permission reference never lists them.

A baseline permission is usable by a console session that has not elevated.
The others need an elevated session acting as a role that holds them (when
elevation is required, the default).

## Roles

| Role | Name | Kind | Description |
|---|---|---|---|
| `platform_owner` | Platform owner | base (super_admin) | Every platform permission. Keep at least two named owners and a break-glass account. |
| `platform_admin` | Platform admin | base (ops_admin) | Day-to-day administration of organizations and accounts; no platform settings, administrators or identity. |
| `platform_viewer` | Read-only | base (readonly) | Reads the console: counts, settings and the audit log, without people's details. |
| `operator` | Operator | additional | Runs the shared sensor fleet and the feeds; suspends an organization for abuse. |
| `support` | Support | additional | Helps people sign in and reads inside support grants organizations give. |
| `security_auditor` | Security auditor | additional | Reads the audit log, administrators and approvals for reviews; changes nothing. |
| `billing` | Billing | additional | Sets organizations' limits and plans. |

## Permissions by role

| Permission | Baseline | `platform_owner` | `platform_admin` | `platform_viewer` | `operator` | `support` | `security_auditor` | `billing` |
|---|---|---|---|---|---|---|---|---|
| `platform.admins.manage` |  | yes |  |  |  |  |  |  |
| `platform.admins.read` |  | yes |  |  |  |  | yes |  |
| `platform.ai_clients.manage` |  | yes | yes |  |  |  |  |  |
| `platform.announcements.write` |  | yes | yes |  |  |  |  |  |
| `platform.approvals.decide` |  | yes |  |  |  |  |  |  |
| `platform.approvals.read` |  | yes |  |  |  |  | yes |  |
| `platform.audit.read` | yes | yes | yes | yes | yes | yes | yes | yes |
| `platform.console.read` | yes | yes | yes | yes | yes | yes | yes | yes |
| `platform.content.manage` |  | yes |  |  |  |  |  |  |
| `platform.feeds.manage` |  | yes | yes |  | yes |  |  |  |
| `platform.identity.manage` |  | yes |  |  |  |  |  |  |
| `platform.roles.assign` |  | yes |  |  |  |  |  |  |
| `platform.roles.read` | yes | yes | yes | yes | yes | yes | yes | yes |
| `platform.sensors.jobs.read` |  | yes | yes |  | yes |  |  |  |
| `platform.sensors.manage` |  | yes |  |  | yes |  |  |  |
| `platform.sensors.read` | yes | yes | yes | yes | yes | yes | yes | yes |
| `platform.settings.ai.write` |  | yes |  |  |  |  |  |  |
| `platform.settings.email.write` |  | yes |  |  |  |  |  |  |
| `platform.settings.general.write` |  | yes |  |  |  |  |  |  |
| `platform.settings.legal.write` |  | yes |  |  |  |  |  |  |
| `platform.settings.limits.write` |  | yes |  |  |  |  |  |  |
| `platform.settings.mfa` |  | yes |  |  |  |  |  |  |
| `platform.settings.read` | yes | yes | yes | yes | yes | yes | yes | yes |
| `platform.settings.signup.write` |  | yes |  |  |  |  |  |  |
| `platform.support.access` |  | yes | yes |  |  | yes |  |  |
| `platform.tenants.audit_chain.write` |  | yes |  |  |  |  |  |  |
| `platform.tenants.create` |  | yes | yes |  |  |  |  |  |
| `platform.tenants.lifecycle` |  | yes | yes |  | yes |  |  |  |
| `platform.tenants.limits.write` |  | yes | yes |  |  |  |  | yes |
| `platform.tenants.members.read` |  | yes | yes |  |  | yes |  |  |
| `platform.tenants.owner_bootstrap` |  | yes | yes |  |  |  |  |  |
| `platform.tenants.owner_recovery` |  | yes |  |  |  |  |  |  |
| `platform.tenants.purge` |  | yes |  |  |  |  |  |  |
| `platform.tenants.read` | yes | yes | yes | yes | yes | yes | yes | yes |
| `platform.tenants.scan_policy.write` |  | yes |  |  |  |  |  |  |
| `platform.tenants.sso.write` |  | yes |  |  |  |  |  |  |
| `platform.users.credentials` |  | yes |  |  |  |  |  |  |
| `platform.users.read` |  | yes | yes |  |  | yes |  |  |
| `platform.users.support` |  | yes | yes |  |  | yes |  |  |

## Permissions

| Permission | What it allows |
|---|---|
| `platform.admins.manage` | Add, change, remove or reset platform administrators; end their console sessions |
| `platform.admins.read` | List platform administrators and console sessions |
| `platform.ai_clients.manage` | Block or unblock an AI client |
| `platform.announcements.write` | Publish or end an announcement |
| `platform.approvals.decide` | Request, approve, reject or withdraw a four-eyes approval |
| `platform.approvals.read` | List four-eyes approval requests |
| `platform.audit.read` | The administrators' audit log and its chain state |
| `platform.console.read` | Overview, operations, system health, version, configuration and the console API reference |
| `platform.content.manage` | Content packs, the content catalog and scanner target mappings |
| `platform.feeds.manage` | Run or switch threat-intelligence feeds |
| `platform.identity.manage` | The administrators' identity provider and the console security-key policy |
| `platform.roles.assign` | Give or take a platform role (never above your own; owner grants need a second owner) |
| `platform.roles.read` | List platform roles and who holds them |
| `platform.sensors.jobs.read` | Open one shared-sensor job's details |
| `platform.sensors.manage` | Pause, resume or retire shared sensors, enrollment tokens, instance scan zones and the shared-sensor settings |
| `platform.sensors.read` | Shared sensors, scan zones, the job queue and the scanning settings |
| `platform.settings.ai.write` | Platform AI and the organizations' AI policy |
| `platform.settings.email.write` | Platform e-mail relay and its test message |
| `platform.settings.general.write` | CAPTCHA, region, alerts, storage quota and the version check |
| `platform.settings.legal.write` | Legal pages |
| `platform.settings.limits.write` | Default limits of self-service organizations |
| `platform.settings.mfa` | The platform two-factor floor every organization is held to |
| `platform.settings.read` | Read every platform setting, announcements, content packs, catalog, target mappings, feeds and AI clients |
| `platform.settings.signup.write` | Sign-up policy, sign-up alert thresholds and the social-login providers |
| `platform.support.access` | Open support sessions inside a grant an organization gave you, and read through them |
| `platform.tenants.audit_chain.write` | Re-sign an organization's audit chain (also needs a second owner's approval) |
| `platform.tenants.create` | Create an organization; approve or reject an access request |
| `platform.tenants.lifecycle` | Suspend or reactivate an organization; rebuild its dashboard figures |
| `platform.tenants.limits.write` | Change an organization's limits, module denies and idle policy |
| `platform.tenants.members.read` | An organization's member list with names and e-mail addresses (otherwise counts only) |
| `platform.tenants.owner_bootstrap` | Create the first owner of an organization that has none |
| `platform.tenants.owner_recovery` | Create an owner for an organization whose owners are all suspended |
| `platform.tenants.purge` | Delete an organization at once (also needs a second owner's approval) |
| `platform.tenants.read` | Organizations: list, details, limits, modules, single sign-on, audit chain state, access requests and the sign-up feed |
| `platform.tenants.scan_policy.write` | Change an organization's scan-approval policy and shared sensors |
| `platform.tenants.sso.write` | Change an organization's SAML, identity providers, verified domains and SSO enforcement |
| `platform.users.credentials` | Account credentials: issue a password-reset link, mark an e-mail verified, reset two-factor (the reset also needs a second owner's approval) |
| `platform.users.read` | Find any account and view its sign-in state, organizations and sessions |
| `platform.users.support` | Account support: end sessions, unlock, send password-reset or verification mail, block or unblock |

## Console routes

`self`: the caller's own session, factors and elevation (a verified console
session, no permission). `public`: a sign-in step before a session exists.

| Route | Permission |
|---|---|
| `GET /api/v1/admin/access-requests/` | `platform.tenants.read` |
| `POST /api/v1/admin/access-requests/{id}/approve` | `platform.tenants.create` |
| `POST /api/v1/admin/access-requests/{id}/reject` | `platform.tenants.create` |
| `POST /api/v1/admin/administrators/` | `platform.admins.manage` |
| `GET /api/v1/admin/announcements/` | `platform.settings.read` |
| `POST /api/v1/admin/announcements/` | `platform.announcements.write` |
| `POST /api/v1/admin/announcements/{announcement_id}/cancel` | `platform.announcements.write` |
| `GET /api/v1/admin/approvals/` | `platform.approvals.read` |
| `POST /api/v1/admin/approvals/` | `platform.approvals.decide` |
| `POST /api/v1/admin/approvals/{id}/approve` | `platform.approvals.decide` |
| `POST /api/v1/admin/approvals/{id}/cancel` | `platform.approvals.decide` |
| `POST /api/v1/admin/approvals/{id}/reject` | `platform.approvals.decide` |
| `GET /api/v1/admin/audit-logs/` | `platform.audit.read` |
| `GET /api/v1/admin/audit-logs/chain` | `platform.audit.read` |
| `GET /api/v1/admin/audit-logs/stats` | `platform.audit.read` |
| `GET /api/v1/admin/audit-logs/{id}` | `platform.audit.read` |
| `DELETE /api/v1/admin/auth/elevate` | `self` |
| `POST /api/v1/admin/auth/elevate` | `self` |
| `GET /api/v1/admin/auth/factors` | `self` |
| `GET /api/v1/admin/auth/idp` | `public` |
| `POST /api/v1/admin/auth/idp/callback` | `public` |
| `POST /api/v1/admin/auth/idp/start` | `public` |
| `POST /api/v1/admin/auth/login` | `public` |
| `POST /api/v1/admin/auth/logout` | `public` |
| `POST /api/v1/admin/auth/mfa` | `public` |
| `POST /api/v1/admin/auth/password` | `self` |
| `POST /api/v1/admin/auth/recovery` | `public` |
| `POST /api/v1/admin/auth/recovery-codes` | `self` |
| `POST /api/v1/admin/auth/step-up/webauthn` | `self` |
| `POST /api/v1/admin/auth/step-up/webauthn/options` | `self` |
| `GET /api/v1/admin/auth/validate` | `self` |
| `POST /api/v1/admin/auth/webauthn/credentials` | `self` |
| `POST /api/v1/admin/auth/webauthn/credentials/options` | `self` |
| `DELETE /api/v1/admin/auth/webauthn/credentials/{id}` | `self` |
| `PATCH /api/v1/admin/auth/webauthn/credentials/{id}` | `self` |
| `POST /api/v1/admin/auth/webauthn/session` | `public` |
| `POST /api/v1/admin/auth/webauthn/session/options` | `public` |
| `GET /api/v1/admin/configuration` | `platform.console.read` |
| `GET /api/v1/admin/console-sessions/` | `platform.admins.read` |
| `DELETE /api/v1/admin/console-sessions/{console_session_id}` | `platform.admins.manage` |
| `GET /api/v1/admin/content-catalog/` | `platform.settings.read` |
| `POST /api/v1/admin/content-catalog/import` | `platform.content.manage` |
| `GET /api/v1/admin/content-catalog/packages` | `platform.settings.read` |
| `POST /api/v1/admin/content-catalog/packages` | `platform.content.manage` |
| `POST /api/v1/admin/content-catalog/packages/revoke` | `platform.content.manage` |
| `GET /api/v1/admin/content-catalog/packages/{namespace}/{name}/versions` | `platform.settings.read` |
| `GET /api/v1/admin/content-packs/` | `platform.settings.read` |
| `POST /api/v1/admin/content-packs/` | `platform.content.manage` |
| `GET /api/v1/admin/content-packs/channels` | `platform.settings.read` |
| `PUT /api/v1/admin/content-packs/channels/{channel}` | `platform.content.manage` |
| `POST /api/v1/admin/content-packs/import` | `platform.content.manage` |
| `GET /api/v1/admin/content-packs/signing-key` | `platform.settings.read` |
| `GET /api/v1/admin/content-packs/{id}` | `platform.settings.read` |
| `GET /api/v1/admin/content-packs/{id}/download` | `platform.settings.read` |
| `POST /api/v1/admin/content-packs/{id}/revoke` | `platform.content.manage` |
| `GET /api/v1/admin/docs` | `platform.console.read` |
| `GET /api/v1/admin/instance-scan-zones/` | `platform.sensors.read` |
| `POST /api/v1/admin/instance-scan-zones/` | `platform.sensors.manage` |
| `DELETE /api/v1/admin/instance-scan-zones/{zone_id}` | `platform.sensors.manage` |
| `GET /api/v1/admin/instance-scan-zones/{zone_id}` | `platform.sensors.read` |
| `PUT /api/v1/admin/instance-scan-zones/{zone_id}` | `platform.sensors.manage` |
| `PUT /api/v1/admin/instance-scan-zones/{zone_id}/organizations` | `platform.sensors.manage` |
| `PUT /api/v1/admin/instance-scan-zones/{zone_id}/sensors` | `platform.sensors.manage` |
| `GET /api/v1/admin/mcp-clients/` | `platform.settings.read` |
| `POST /api/v1/admin/mcp-clients/{id}/block` | `platform.ai_clients.manage` |
| `POST /api/v1/admin/mcp-clients/{id}/unblock` | `platform.ai_clients.manage` |
| `GET /api/v1/admin/openapi.yaml` | `platform.console.read` |
| `GET /api/v1/admin/operations` | `platform.console.read` |
| `GET /api/v1/admin/overview` | `platform.console.read` |
| `DELETE /api/v1/admin/platform-idp/` | `platform.identity.manage` |
| `GET /api/v1/admin/platform-idp/` | `platform.identity.manage` |
| `PUT /api/v1/admin/platform-idp/` | `platform.identity.manage` |
| `GET /api/v1/admin/platform-roles/` | `platform.roles.read` |
| `GET /api/v1/admin/platform-roles/assignments` | `platform.admins.read` |
| `GET /api/v1/admin/platform-users/` | `platform.users.read` |
| `GET /api/v1/admin/platform-users/{user_id}` | `platform.users.read` |
| `POST /api/v1/admin/platform-users/{user_id}/block` | `platform.users.support` |
| `POST /api/v1/admin/platform-users/{user_id}/mark-verified` | `platform.users.credentials` |
| `POST /api/v1/admin/platform-users/{user_id}/mfa/reset` | `platform.users.credentials` |
| `POST /api/v1/admin/platform-users/{user_id}/password-reset` | `platform.users.support` |
| `POST /api/v1/admin/platform-users/{user_id}/reset-link` | `platform.users.credentials` |
| `POST /api/v1/admin/platform-users/{user_id}/revoke-sessions` | `platform.users.support` |
| `POST /api/v1/admin/platform-users/{user_id}/unblock` | `platform.users.support` |
| `POST /api/v1/admin/platform-users/{user_id}/unlock` | `platform.users.support` |
| `POST /api/v1/admin/platform-users/{user_id}/verification-emails` | `platform.users.support` |
| `GET /api/v1/admin/settings/ai/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/ai/` | `platform.settings.ai.write` |
| `PUT /api/v1/admin/settings/ai/org-policy` | `platform.settings.ai.write` |
| `POST /api/v1/admin/settings/ai/test` | `platform.settings.ai.write` |
| `GET /api/v1/admin/settings/alerts/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/alerts/` | `platform.settings.general.write` |
| `POST /api/v1/admin/settings/alerts/test` | `platform.settings.general.write` |
| `GET /api/v1/admin/settings/auth-mfa/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/auth-mfa/` | `platform.settings.mfa` |
| `GET /api/v1/admin/settings/captcha/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/captcha/` | `platform.settings.general.write` |
| `POST /api/v1/admin/settings/captcha/verify` | `platform.settings.general.write` |
| `GET /api/v1/admin/settings/console-mfa/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/console-mfa/` | `platform.identity.manage` |
| `GET /api/v1/admin/settings/email-relay/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/email-relay/` | `platform.settings.email.write` |
| `GET /api/v1/admin/settings/email/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/email/` | `platform.settings.email.write` |
| `POST /api/v1/admin/settings/email/test` | `platform.settings.email.write` |
| `GET /api/v1/admin/settings/legal/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/legal/` | `platform.settings.legal.write` |
| `GET /api/v1/admin/settings/limits/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/limits/` | `platform.settings.limits.write` |
| `GET /api/v1/admin/settings/platform-sensor-proof/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/platform-sensor-proof/` | `platform.sensors.manage` |
| `GET /api/v1/admin/settings/region/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/region/` | `platform.settings.general.write` |
| `GET /api/v1/admin/settings/scan-approval-policy/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/scan-approval-policy/` | `platform.sensors.manage` |
| `GET /api/v1/admin/settings/shared-sensor-anomaly/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/shared-sensor-anomaly/` | `platform.sensors.manage` |
| `GET /api/v1/admin/settings/shared-sensor-internal-zones/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/shared-sensor-internal-zones/` | `platform.sensors.manage` |
| `GET /api/v1/admin/settings/shared-sensors/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/shared-sensors/` | `platform.sensors.manage` |
| `GET /api/v1/admin/settings/shared-sensors/egress` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/shared-sensors/egress` | `platform.sensors.manage` |
| `GET /api/v1/admin/settings/signup-alerts/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/signup-alerts/` | `platform.settings.signup.write` |
| `GET /api/v1/admin/settings/signup/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/signup/` | `platform.settings.signup.write` |
| `GET /api/v1/admin/settings/social-login-providers/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/social-login-providers/{provider}` | `platform.settings.signup.write` |
| `POST /api/v1/admin/settings/social-login-providers/{provider}/test` | `platform.settings.signup.write` |
| `GET /api/v1/admin/settings/storage-quota/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/storage-quota/` | `platform.settings.general.write` |
| `GET /api/v1/admin/settings/threat-intel-source/` | `platform.settings.read` |
| `PUT /api/v1/admin/settings/threat-intel-source/` | `platform.settings.general.write` |
| `GET /api/v1/admin/shared-sensors/` | `platform.sensors.read` |
| `POST /api/v1/admin/shared-sensors/enrollment-tokens` | `platform.sensors.manage` |
| `GET /api/v1/admin/shared-sensors/jobs` | `platform.sensors.read` |
| `POST /api/v1/admin/shared-sensors/jobs/{job_id}/view` | `platform.sensors.jobs.read` |
| `GET /api/v1/admin/shared-sensors/queue` | `platform.sensors.read` |
| `POST /api/v1/admin/shared-sensors/{sensor_id}/disable` | `platform.sensors.manage` |
| `POST /api/v1/admin/shared-sensors/{sensor_id}/enable` | `platform.sensors.manage` |
| `POST /api/v1/admin/shared-sensors/{sensor_id}/revoke` | `platform.sensors.manage` |
| `GET /api/v1/admin/signup-events/` | `platform.tenants.read` |
| `GET /api/v1/admin/signup-events/daily` | `platform.tenants.read` |
| `GET /api/v1/admin/support/grants` | `platform.support.access` |
| `POST /api/v1/admin/support/grants/{grant_id}/sessions` | `platform.support.access` |
| `DELETE /api/v1/admin/support/sessions/{session_id}` | `platform.support.access` |
| `GET /api/v1/admin/support/sessions/{session_id}/assets` | `platform.support.access` |
| `GET /api/v1/admin/support/sessions/{session_id}/assets/{id}` | `platform.support.access` |
| `GET /api/v1/admin/support/sessions/{session_id}/findings` | `platform.support.access` |
| `GET /api/v1/admin/support/sessions/{session_id}/findings/{id}` | `platform.support.access` |
| `GET /api/v1/admin/support/sessions/{session_id}/overview` | `platform.support.access` |
| `GET /api/v1/admin/system` | `platform.console.read` |
| `GET /api/v1/admin/target-mappings/` | `platform.settings.read` |
| `POST /api/v1/admin/target-mappings/` | `platform.content.manage` |
| `GET /api/v1/admin/target-mappings/registry` | `platform.settings.read` |
| `GET /api/v1/admin/target-mappings/stats` | `platform.settings.read` |
| `GET /api/v1/admin/target-mappings/types` | `platform.settings.read` |
| `DELETE /api/v1/admin/target-mappings/{id}` | `platform.content.manage` |
| `GET /api/v1/admin/target-mappings/{id}` | `platform.settings.read` |
| `PATCH /api/v1/admin/target-mappings/{id}` | `platform.content.manage` |
| `GET /api/v1/admin/tenants/` | `platform.tenants.read` |
| `POST /api/v1/admin/tenants/` | `platform.tenants.create` |
| `GET /api/v1/admin/tenants/{tenantId}` | `platform.tenants.read` |
| `GET /api/v1/admin/tenants/{tenantId}/audit-chain` | `platform.tenants.read` |
| `POST /api/v1/admin/tenants/{tenantId}/audit-chain/rebaseline` | `platform.tenants.audit_chain.write` |
| `GET /api/v1/admin/tenants/{tenantId}/dashboard-data` | `platform.tenants.read` |
| `POST /api/v1/admin/tenants/{tenantId}/dashboard-data/rebuild` | `platform.tenants.lifecycle` |
| `GET /api/v1/admin/tenants/{tenantId}/idle` | `platform.tenants.read` |
| `PUT /api/v1/admin/tenants/{tenantId}/idle/policy` | `platform.tenants.limits.write` |
| `GET /api/v1/admin/tenants/{tenantId}/limits` | `platform.tenants.read` |
| `DELETE /api/v1/admin/tenants/{tenantId}/limits/{key}` | `platform.tenants.limits.write` |
| `PUT /api/v1/admin/tenants/{tenantId}/limits/{key}` | `platform.tenants.limits.write` |
| `GET /api/v1/admin/tenants/{tenantId}/modules` | `platform.tenants.read` |
| `DELETE /api/v1/admin/tenants/{tenantId}/modules/{module_id}/deny` | `platform.tenants.limits.write` |
| `PUT /api/v1/admin/tenants/{tenantId}/modules/{module_id}/deny` | `platform.tenants.limits.write` |
| `POST /api/v1/admin/tenants/{tenantId}/purge` | `platform.tenants.purge` |
| `GET /api/v1/admin/tenants/{tenantId}/scan-approval-policy` | `platform.tenants.read` |
| `PUT /api/v1/admin/tenants/{tenantId}/scan-approval-policy` | `platform.tenants.scan_policy.write` |
| `GET /api/v1/admin/tenants/{tenantId}/shared-sensors` | `platform.tenants.read` |
| `PUT /api/v1/admin/tenants/{tenantId}/shared-sensors` | `platform.tenants.scan_policy.write` |
| `GET /api/v1/admin/tenants/{tenantId}/sso/changes` | `platform.tenants.read` |
| `GET /api/v1/admin/tenants/{tenantId}/sso/enforcement` | `platform.tenants.read` |
| `PUT /api/v1/admin/tenants/{tenantId}/sso/enforcement` | `platform.tenants.sso.write` |
| `GET /api/v1/admin/tenants/{tenantId}/sso/identity-providers` | `platform.tenants.read` |
| `POST /api/v1/admin/tenants/{tenantId}/sso/identity-providers` | `platform.tenants.sso.write` |
| `DELETE /api/v1/admin/tenants/{tenantId}/sso/identity-providers/{id}` | `platform.tenants.sso.write` |
| `GET /api/v1/admin/tenants/{tenantId}/sso/identity-providers/{id}` | `platform.tenants.read` |
| `PUT /api/v1/admin/tenants/{tenantId}/sso/identity-providers/{id}` | `platform.tenants.sso.write` |
| `DELETE /api/v1/admin/tenants/{tenantId}/sso/saml` | `platform.tenants.sso.write` |
| `GET /api/v1/admin/tenants/{tenantId}/sso/saml` | `platform.tenants.read` |
| `PUT /api/v1/admin/tenants/{tenantId}/sso/saml` | `platform.tenants.sso.write` |
| `GET /api/v1/admin/tenants/{tenantId}/sso/verified-domains` | `platform.tenants.read` |
| `POST /api/v1/admin/tenants/{tenantId}/sso/verified-domains` | `platform.tenants.sso.write` |
| `DELETE /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}` | `platform.tenants.sso.write` |
| `PATCH /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}` | `platform.tenants.sso.write` |
| `POST /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}/verify` | `platform.tenants.sso.write` |
| `POST /api/v1/admin/tenants/{tenantId}/suspend` | `platform.tenants.lifecycle` |
| `POST /api/v1/admin/tenants/{tenantId}/unsuspend` | `platform.tenants.lifecycle` |
| `GET /api/v1/admin/tenants/{tenantId}/users` | `platform.tenants.read` |
| `POST /api/v1/admin/tenants/{tenantId}/users` | `platform.tenants.owner_bootstrap` |
| `GET /api/v1/admin/threat-intel/sync` | `platform.settings.read` |
| `POST /api/v1/admin/threat-intel/sync` | `platform.feeds.manage` |
| `PATCH /api/v1/admin/threat-intel/sync/{source}` | `platform.feeds.manage` |
| `GET /api/v1/admin/users/` | `platform.admins.read` |
| `DELETE /api/v1/admin/users/{id}` | `platform.admins.manage` |
| `GET /api/v1/admin/users/{id}` | `platform.admins.read` |
| `PATCH /api/v1/admin/users/{id}` | `platform.admins.manage` |
| `POST /api/v1/admin/users/{id}/break-glass-test` | `platform.admins.manage` |
| `DELETE /api/v1/admin/users/{id}/idp-binding` | `platform.admins.manage` |
| `POST /api/v1/admin/users/{id}/platform-roles` | `platform.roles.assign` |
| `DELETE /api/v1/admin/users/{id}/platform-roles/{role}` | `platform.roles.assign` |
| `POST /api/v1/admin/users/{id}/reset-credentials` | `platform.admins.manage` |
| `GET /api/v1/admin/version` | `platform.console.read` |
| `GET /api/v1/admin/version-check/` | `platform.settings.read` |
| `PUT /api/v1/admin/version-check/enabled` | `platform.settings.general.write` |
| `POST /api/v1/admin/version-check/import` | `platform.settings.general.write` |
