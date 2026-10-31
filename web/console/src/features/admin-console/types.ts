/**
 * Platform admin console types (RFC-022). The console talks only to
 * /api/v1/admin/* through its own proxy; nothing here is tenant-scoped.
 */

import type { SetupLinkOutcome } from '@/features/shared/components/one-time-setup-link'

export type AdminRole = 'super_admin' | 'ops_admin' | 'readonly'

export interface AdminIdentity {
  id: string
  email: string
  name: string
  role: AdminRole
  /** How this console session was opened. */
  auth_method?: 'password' | 'idp'
  /** Emergency-access (break-glass) administrator: every sign-in is alerted. */
  is_break_glass?: boolean
  /** The session may only change the temporary password. */
  password_change_required?: boolean
  /** The console requires security keys: only the enrollment page works until they are registered. */
  factor_enrollment_required?: boolean
  /** The administrator's own role: the most the session may elevate to. `role` is what it acts as now. */
  max_role?: AdminRole
  /** When the session's elevation ends (absent: not elevated). */
  elevated_until?: string
  /** The platform role the session is elevated as (absent: not elevated). */
  elevated_as?: string
  /** Platform roles held (RFC-134). */
  roles?: string[]
  /** Platform permissions the session acts with now. */
  permissions?: string[]
  /** Everything the roles grant: the most an elevation reaches. */
  max_permissions?: string[]
  /** The session's CSRF token (sign-in and validate only); kept in memory by admin-client. */
  csrf_token?: string
}

/** A second factor a sign-in may use, in the API's order of preference. */
export type AdminSignInMethod = 'webauthn' | 'totp' | 'recovery_code'

export type AdminLoginStatus = 'mfa_required' | 'mfa_enrollment_required'

/** Outcome of the identity-provider callback. */
export interface AdminIdPCallbackResult {
  /** signed_in: the IdP's MFA was trusted and the console session is open. */
  status: AdminLoginStatus | 'signed_in'
  otpauth_uri?: string
  secret?: string
  admin?: AdminIdentity
}

/** What the console sign-in page may know about the administrators' IdP. */
export interface AdminIdPInfo {
  enabled: boolean
  display_name?: string
}

/** The administrators' identity provider (RFC-022 revision 4). */
export interface PlatformIdP {
  configured: boolean
  enabled: boolean
  display_name?: string
  issuer?: string
  client_id?: string
  /** The secret itself is write-only and never returned. */
  has_client_secret: boolean
  redirect_uri?: string
  scopes?: string[]
  require_idp: boolean
  trusted_acr_values: string[]
  trusted_amr_values: string[]
  authorization_endpoint?: string
  token_endpoint?: string
  jwks_uri?: string
  token_endpoint_auth_method?: string
  updated_at?: string
}

export interface PlatformIdPInput {
  enabled: boolean
  display_name: string
  issuer: string
  client_id: string
  /** Empty keeps the stored secret. */
  client_secret?: string
  redirect_uri: string
  scopes?: string[]
  require_idp: boolean
  trusted_acr_values?: string[]
  trusted_amr_values?: string[]
}

export interface AdminLoginResult {
  status: AdminLoginStatus
  /** Only for mfa_enrollment_required. */
  otpauth_uri?: string
  secret?: string
  /** The second factors this administrator may use, preferred first. */
  methods?: AdminSignInMethod[]
}

export interface AdminOrganization {
  id: string
  name: string
  slug: string
  description?: string
  created_at: string
  active_members: number
  /**
   * Owners' addresses: only on the organization's own page, for ops_admin and
   * above (that view is audited). Empty in the list and for read-only.
   */
  owner_emails: string[]
  /** Distinct domains of the owners' addresses (list column); empty for read-only. */
  owner_domains: string[]
  owner_count: number
  saml_enabled: boolean
  active_identity_providers: number
  verified_domains: number
  sso_enforced: boolean
  /** At least one limit or module deny is set for the organization. */
  limits_apply: boolean
  /** Platform status: a suspended organization is refused to every credential. */
  status: 'active' | 'suspended' | 'pending_deletion'
  suspended_at?: string
  /** ops_admin and above; read-only administrators and members never get it. */
  suspended_reason?: string
  /** An owner scheduled the deletion for this time. */
  deletion_due_at?: string
}

export interface AdminOrganizationList {
  data: AdminOrganization[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface CreateOrganizationInput {
  name: string
  slug: string
  description?: string
  /** May be someone without an account yet: the API creates it. */
  owner_email: string
  /** Name for a newly created owner account. */
  owner_name?: string
}

/**
 * POST /admin/tenants response. `owner_setup` is present when the owner's
 * account was created by this call; its `setup_token` (no email sent) is shown
 * once and never stored.
 */
export interface CreatedOrganization extends AdminOrganization {
  owner_setup?: SetupLinkOutcome
}

/** Membership level an admin can give someone they add to an organization. */

export interface AdminOrganizationUser {
  user_id: string
  email: string
  name: string
  /** owner | admin | member | viewer */
  role: string
  status: string
  pending_setup: boolean
  joined_at: string
}

export interface AdminOrganizationUserList {
  /** Empty when redacted: a read-only administrator sees counts only. */
  data: AdminOrganizationUser[]
  by_role: Record<string, number>
  /**
   * Owners who can act: active membership, account active and not erased.
   * Zero while owners exist means the organization needs an owner recovery.
   * Every role gets it, also the read-only one that gets no rows.
   */
  active_owner_count?: number
  redacted?: boolean
  total: number
}

/**
 * POST /admin/tenants/{id}/users: the platform console only creates the FIRST
 * owner of an organization that has none (409 otherwise). No role choice.
 */
export interface AdminCreateOrganizationUserInput {
  email: string
  name: string
}

/** Owner recovery: a new owner when every owner is suspended (super admin). */
export interface AdminOwnerRecoveryInput {
  email: string
  name: string
  reason: string
  totp_code?: string
}

/** Same shape as the tenant-side create-user response. */
export interface AdminCreatedOrganizationUser extends SetupLinkOutcome {
  user: { id: string; email: string; name: string }
  membership_id: string
  role: string
}

/** English names of the console roles (i18n keys admin.role.<role>). */
export const ADMIN_ROLE_LABELS: Record<AdminRole, string> = {
  super_admin: 'Super admin',
  ops_admin: 'Operations admin',
  readonly: 'Read-only admin',
}

/**
 * The base tier that held each platform permission before platform roles. Only
 * used for an identity that carries no permission list; the API always sends
 * one, so this keeps hand-built identities (tests, stories) meaningful.
 */
const PERMISSION_MIN_TIER: Record<string, AdminRole> = {
  'platform.console.read': 'readonly',
  'platform.tenants.read': 'readonly',
  'platform.roles.read': 'readonly',
  'platform.settings.read': 'readonly',
  'platform.sensors.read': 'readonly',
  'platform.audit.read': 'readonly',
  'platform.tenants.members.read': 'ops_admin',
  'platform.tenants.create': 'ops_admin',
  'platform.tenants.lifecycle': 'ops_admin',
  'platform.tenants.owner_bootstrap': 'ops_admin',
  'platform.tenants.limits.write': 'ops_admin',
  'platform.users.read': 'ops_admin',
  'platform.users.support': 'ops_admin',
  'platform.announcements.write': 'ops_admin',
  'platform.sensors.jobs.read': 'ops_admin',
  'platform.feeds.manage': 'ops_admin',
  'platform.ai_clients.manage': 'ops_admin',
  'platform.support.access': 'ops_admin',
}

/**
 * Whether the session acts with platform permission p now (RFC-134). Hiding is
 * a convenience: the API decides on its own.
 */
export function adminHas(admin: AdminIdentity | null | undefined, p: string): boolean {
  if (!admin) return false
  if (admin.permissions) return admin.permissions.includes(p)
  return adminCan(admin.role, PERMISSION_MIN_TIER[p] ?? 'super_admin')
}

/** Whether an elevation could give the session platform permission p. */
export function adminMayHave(admin: AdminIdentity | null | undefined, p: string): boolean {
  if (!admin) return false
  if (admin.max_permissions) return admin.max_permissions.includes(p)
  return adminCan(admin.max_role ?? admin.role, PERMISSION_MIN_TIER[p] ?? 'super_admin')
}

/** Whether an elevation would give the session more than it acts with now. */
export function adminCanElevate(admin: AdminIdentity | null | undefined): boolean {
  if (!admin || admin.elevated_until) return false
  if (admin.max_permissions && admin.permissions) {
    const now = admin.permissions
    return admin.max_permissions.some((p) => !now.includes(p))
  }
  return admin.role === 'readonly' && (admin.max_role ?? admin.role) !== 'readonly'
}

/** The built-in platform roles, in display order (RFC-134). */
export const PLATFORM_ROLE_KEYS = [
  'platform_owner',
  'platform_admin',
  'platform_viewer',
  'operator',
  'support',
  'security_auditor',
  'billing',
] as const

/**
 * The roles a session may elevate as: each held role but the read-only one,
 * and the admin role for an owner. An identity without roles (an older API)
 * gets the tier names.
 */
export function elevationChoices(admin: AdminIdentity): string[] {
  if (!admin.roles) {
    const max = admin.max_role ?? admin.role
    return (['super_admin', 'ops_admin'] as AdminRole[]).filter((r) => adminCan(max, r))
  }
  const held = new Set(admin.roles)
  if (held.has('platform_owner')) held.add('platform_admin')
  return PLATFORM_ROLE_KEYS.filter((k) => k !== 'platform_viewer' && held.has(k))
}

/** super_admin > ops_admin > readonly. */
export function adminCan(role: AdminRole | undefined, needed: AdminRole): boolean {
  const rank: Record<AdminRole, number> = { readonly: 0, ops_admin: 1, super_admin: 2 }
  return role !== undefined && rank[role] >= rank[needed]
}

export interface AdminUserRecord {
  id: string
  email: string
  name: string
  role: AdminRole
  is_active: boolean
  last_used_at?: string
  last_used_ip?: string
  created_at: string
  updated_at: string
  is_break_glass: boolean
  break_glass_tested_at?: string
  break_glass_test_overdue: boolean
  password_change_required: boolean
  idp_bound: boolean
  idp_bound_at?: string
}

export interface Paged<T> {
  data: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

/** The Users list's state tabs (the API's `state` values). */
export const PLATFORM_USER_STATES = [
  'all',
  'active',
  'unverified',
  'locked',
  'blocked',
  'mfa_off',
  'platform_admins',
] as const
export type PlatformUserState = (typeof PLATFORM_USER_STATES)[number]

/** One account in the Users list: no name, no organization data. */
export interface PlatformUserListItem {
  id: string
  email: string
  status: string
  auth_provider: string
  email_verified: boolean
  locked: boolean
  blocked: boolean
  last_login_at?: string
  created_at: string
  memberships: number
  mfa_enabled: boolean
  is_platform_admin: boolean
  erased: boolean
}

/** A page of the Users list with the count of each state under the search. */
export interface PlatformUserList extends Paged<PlatformUserListItem> {
  counts: Partial<Record<PlatformUserState, number>>
}

export interface AdminAuditEntry {
  id: string
  admin_id?: string
  admin_email: string
  action: string
  resource_type?: string
  resource_id?: string
  resource_name?: string
  request_method?: string
  request_path?: string
  response_status?: number
  ip_address?: string
  success: boolean
  error_message?: string
  created_at: string
}

/** Scanner target type -> asset type (GET /admin/target-mappings). */
export interface TargetMapping {
  id: string
  target_type: string
  asset_type: string
  /** Lower sorts first; 10 is the primary mapping. */
  priority: number
  is_active: boolean
  is_primary: boolean
  description?: string
  created_by?: string
  created_at: string
  updated_at: string
}

/** One pair of the asset type catalog: read-only, changes with a release. */
export interface RegistryTargetPair {
  target_type: string
  asset_type: string
  sub_type?: string
}

export interface TargetMappingStats {
  total: number
  by_target_type: Record<string, number>
  by_asset_type: Record<string, number>
  active_count: number
  inactive_count: number
}

export interface CreateTargetMappingInput {
  target_type: string
  asset_type: string
  priority?: number
  is_active?: boolean
  description?: string
  /** Why the mapping is added (10 to 500 characters); kept in the audit row. */
  reason: string
}

/** The pair (target type, asset type) cannot change after creation. */
export interface UpdateTargetMappingInput {
  priority?: number
  is_active?: boolean
  description?: string
  /** Why the mapping changes (10 to 500 characters); kept in the audit row. */
  reason: string
}

/** GET /admin/target-mappings/types: the values the API accepts. */
export interface TargetMappingTypes {
  target_types: string[]
  asset_types: string[]
}

/** GET /admin/overview: the console's attention counts (any admin role). */
export interface AdminOverview {
  organizations: {
    total: number
    without_owner: number
    without_owner_sample: { id: string; name: string }[]
  }
  security: {
    break_glass_sign_ins_7d: number
    failed_admin_actions_24h: number
    break_glass_tests_overdue: number
  }
  /** What waits in the Requests inbox. */
  requests?: {
    access_pending: number
    access_oldest_pending_seconds: number
  }
  platform: {
    schema_version: number
    /** Newest migration the running API ships; 0 when unknown. */
    schema_shipped: number
    schema_dirty: boolean
    schema_known: boolean
    platform_sensors: { total: number; online: number; offline: number }
    commands_pending: number
    command_oldest_pending_seconds: number
    scan_runs_past_deadline: number
    outbox_failed: number
    outbox_dead: number
  }
  generated_at: string
}

/** One account in Console > Users (account-level facts only). */
export interface PlatformUser {
  id: string
  email: string
  name: string
  status: string
  /** local | oidc | google | github | microsoft | saml */
  auth_provider: string
  email_verified: boolean
  locked: boolean
  locked_until?: string
  failed_logins: number
  last_login_at?: string
  created_at: string
  memberships: number
  mfa_enabled: boolean
  is_platform_admin: boolean
  erased: boolean
  /** Blocked platform-wide: no sign-in, API key or MCP token anywhere. */
  blocked: boolean
  blocked_at?: string
  blocked_reason?: string
}

export interface PlatformUserDetail extends PlatformUser {
  /** The server can send email. False: copy a reset link, mark email verified. */
  email_delivery?: boolean
  membership_list: {
    tenant_id: string
    tenant_name: string
    tenant_slug: string
    role: string
    status: string
    joined_at: string
  }[]
  identities: {
    issuer: string
    subject: string
    tenant_id?: string
    created_at: string
    last_used_at?: string
  }[]
  sessions: {
    id: string
    ip_address?: string
    user_agent?: string
    auth_method: string
    created_at: string
    last_activity_at: string
    expires_at: string
  }[]
}

export type PlatformUserAction =
  | 'revoke-sessions'
  | 'unlock'
  | 'password-reset'
  | 'verification-emails'
  | 'block'
  | 'unblock'
  | 'mark-verified'
  | 'mfa/reset'

/** POST /admin/platform-users/{id}/reset-link: shown once, never stored. */
export interface PlatformUserResetLink {
  link: string
  expires_at: string
}

/** GET /admin/sessions: one open console session (super admin). */
export interface AdminConsoleSession {
  id: string
  admin_id: string
  admin_email: string
  admin_name: string
  admin_role: AdminRole
  break_glass: boolean
  /** password | idp */
  auth_method: string
  mfa_verified: boolean
  ip_address?: string
  user_agent?: string
  created_at: string
  last_seen_at: string
  expires_at: string
  /** The session making the request. */
  current: boolean
}

/** The protected actions of four-eyes approvals. */
export type AdminApprovalAction =
  | 'admin.grant_super_admin'
  | 'admin.revoke_super_admin'
  | 'console_mfa.disable'
  | 'platform_idp.remove'
  | 'platform_idp.change'
  | 'admin.reset_credentials'
  | 'signup.open'
  | 'audit_chain.rebaseline'
  | 'organization.purge'
  | 'user.reset_mfa'

export type AdminApprovalStatus =
  'pending' | 'approved' | 'rejected' | 'canceled' | 'expired' | 'used'

/** GET /admin/approvals: one request for a second super admin's approval. */
export interface AdminApproval {
  id: string
  action: AdminApprovalAction | string
  target: string
  target_label?: string
  reason: string
  status: AdminApprovalStatus
  requested_by_id: string
  requested_by_email?: string
  requested_at: string
  expires_at: string
  decided_by_email?: string
  decided_at?: string
  decision_note?: string
  used_at?: string
  /** The caller asked: may cancel, never decide. */
  mine: boolean
}

export interface AdminApprovalList {
  four_eyes: {
    /** Another super admin can approve the caller's requests. */
    active: boolean
    /** Active, named (not break-glass) super admins. */
    approvers: number
    /** The caller may approve others' requests (not break-glass). */
    can_approve: boolean
  }
  ttl_hours: number
  data: AdminApproval[]
}

interface AdminOpsComponent {
  ok: boolean
  latency_ms: number
  configured: boolean
  error?: string
}

/** GET /admin/operations: the installation's health (any admin role). */
export interface AdminOperations {
  build: { version: string; commit?: string; build_time?: string; channel?: string }
  schema: { applied: number; shipped: number; dirty: boolean; known: boolean }
  database: AdminOpsComponent & {
    open_connections: number
    in_use: number
    idle: number
    max_open: number
    wait_count: number
  }
  redis: AdminOpsComponent
  queues: {
    commands_pending: number
    commands_running: number
    command_oldest_pending_seconds: number
    scan_runs_open: number
    scan_runs_past_deadline: number
    outbox_pending: number
    outbox_failed: number
    outbox_dead: number
    outbox_oldest_pending_seconds: number
  }
  sensors: {
    platform: boolean
    health: string
    config_health?: string
    sdk_version?: string
    count: number
  }[]
  /** SDK releases with a published security advisory. */
  sdk_advisories?: string[]
  /** How sensors reach this installation; absent when not wired. */
  sensor_transport?: AdminSensorTransport
  controllers: {
    name: string
    running: boolean
    last_reconcile_at?: string
    errors_total: number
  }[]
  checked_at: string
}

/** The sensor protocol v3 bindings and the gRPC self-probe (api RFC-059). */
export interface AdminSensorTransport {
  /** auto: protocol v3 served; off: every sensor on protocol v2. */
  mode: 'auto' | 'off'
  https_path?: string
  grpc: {
    /** advertised: offered to sensors; pending: first probe; unavailable: see reason. */
    state: 'advertised' | 'pending' | 'unavailable'
    endpoint?: string
    requires_alpn?: boolean
    reason?: string
    checked_at?: string
  }
}

/** A platform announcement in the console (GET /admin/announcements). */
export interface AdminAnnouncement {
  id: string
  message: string
  severity: 'info' | 'warning' | 'maintenance'
  starts_at: string
  ends_at?: string
  state: 'scheduled' | 'active' | 'ended'
  created_at: string
}

/** One threat-intelligence feed's sync state (GET /admin/threat-intel/sync). */
export type ThreatIntelFeedState =
  'up_to_date' | 'waiting_for_publisher' | 'stale' | 'failing' | 'refused' | 'running' | 'off'

/** One upstream source named by the applied vulnerability bundle. */
export interface ThreatIntelBundleSource {
  name: string
  as_of?: string
  fresh: boolean
}

/** The vulnerability bundle feed's own progress. */
export interface ThreatIntelBundleDetail {
  applied_sequence: number
  keyset_version: number
  root_key_id?: string
  kind?: string
  bundle_created_at?: string
  sources: ThreatIntelBundleSource[]
}

/** A platform-wide intelligence feed as the server computes its status. */
export interface ThreatIntelFeed {
  source: string
  enabled: boolean
  state: ThreatIntelFeedState
  /** Classifies the last failure; `error_params` fills its message. */
  error_code?: string
  error_params?: Record<string, string>
  /** The raw text of the last failure (platform admin route only). */
  last_error?: string
  last_attempt_at?: string
  last_success_at?: string
  failing_since?: string
  next_run_at?: string
  /** Size of the stored catalog, and what the last run wrote. */
  catalog_records: number
  records_changed: number
  data_as_of?: string
  interval_seconds: number
  stale_after_seconds: number
  detail?: ThreatIntelBundleDetail
}

/** A release in the signed release feed. */
export interface ReleaseFeedRelease {
  version: string
  published_at: string
  notes_url?: string
}

/** A security advisory in the signed release feed. */
export interface ReleaseFeedAdvisory {
  id: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  introduced?: string
  fixed_in: string
  published_at: string
  url?: string
}

/** Error codes of the last online check or of a refused import. */
export type VersionCheckErrorCode =
  | 'unreachable'
  | 'not_published'
  | 'http_status'
  | 'too_large'
  | 'invalid'
  | 'rollback'
  | 'conflict'
  | 'expired'
  | 'no_key'

/** GET /admin/version-check/: what the release feed says about this instance. */
/** The newest release of one first-party component (a sensor product, the SDK). */
export interface ReleaseFeedComponent {
  /** The versions.yaml section: "sensor", "connector-tenable", "sdk". */
  component: string
  version: string
  published_at: string
  notes_url?: string
  /** Image manifest digest the install snippets pin ("sha256:..."). */
  digest?: string
}

export interface VersionCheckStatus {
  enabled: boolean
  /** VERSION_CHECK_ENABLED=false keeps the online check off; the console cannot turn it on. */
  locked_by_environment?: boolean
  configured: boolean
  feed_url: string
  source?: 'online' | 'import'
  applied_at?: string
  feed_issued_at?: string
  feed_expires_at?: string
  last_attempt_at?: string
  last_error?: VersionCheckErrorCode
  next_check_at?: string
  running: string
  comparable: boolean
  latest?: string
  update_available: boolean
  newer: ReleaseFeedRelease[]
  /** Newest release of each first-party sensor product and the SDK, from the applied feed. */
  components?: ReleaseFeedComponent[]
  advisories: ReleaseFeedAdvisory[]
  severity?: ReleaseFeedAdvisory['severity']
  fixed_in?: string
  stale: boolean
}

/** GET /admin/system: service health, storage, backup, certificates and version (any admin role, read-only; RFC-114). */
export interface AdminSystem {
  services: {
    name: 'api' | 'postgres' | 'redis' | 'web' | 'gateway' | 'sensors'
    configured: boolean
    ok: boolean
    latency_ms: number
    code?: 'unreachable' | 'unhealthy' | 'unreadable'
    /** Connected (online) sensors for the sensors row. */
    detail?: number
  }[]
  storage: {
    volumes: {
      name: string
      ok: boolean
      total_bytes: number
      used_bytes: number
      free_bytes: number
      free_ratio: number
      /** 0 ok, 1 warning, 2 critical. */
      level: number
    }[]
    database_bytes: number
    database_ok: boolean
  }
  backup: {
    reported: boolean
    last_success_at?: string
    age_seconds?: number
    last_failed?: boolean
    level: number
  }
  certificates: {
    name: string
    ok: boolean
    not_after?: string
    expires_in_seconds?: number
    level: number
  }[]
  version: {
    running: string
    channel?: string
    check?: {
      enabled: boolean
      configured: boolean
      last_attempt_at?: string
      last_error?: string
      /** Last time a verified release feed was applied (last success). */
      applied_at?: string
      latest?: string
      update_available: boolean
      advisories: number
      severity?: string
      stale: boolean
    }
  }
  level: number
  checked_at: string
}

/** One row of GET /admin/configuration (RFC-022 revision 22). Secrets come back as is_set only. */
export interface ConfigurationItem {
  key: string
  group:
    | 'instance'
    | 'sign_in'
    | 'email'
    | 'scanning'
    | 'storage'
    | 'ai'
    | 'console'
    | 'audit'
    | 'updates'
    | 'alerts'
  managed: 'console' | 'server'
  source: 'console' | 'environment' | 'default'
  value?: string
  secret?: boolean
  is_set?: boolean
  env_var?: string
  ceiling?: boolean
  /** The environment variable that pins this console setting, when set. */
  locked_by?: string
  restart_required: boolean
  page?: string
  planned?: boolean
  changed_at?: string
  changed_by?: string
}

/** Who changed a console setting and when (absent: never in the console). */
export interface SettingChange {
  changed_at?: string
  changed_by?: string
}

/** The lowest two-factor requirement of every organization; organizations may only raise it. */
export type MFAFloor = 'none' | 'admins' | 'everyone'

/** Settings > Two-factor: the platform floor (GET/PUT /admin/settings/auth-mfa). */
export interface MFAFloorSettings extends SettingChange {
  floor: MFAFloor
  /** console, migration or default */
  source: string
  default: MFAFloor
  env_var: string
  grace_days_existing: number
  grace_days_new: number
  effective_from?: string
  /** An upgraded install still on the seeded "none": raising it is recommended. */
  recommend_raise: boolean
  version: number
}

/** Whether an organization's own mail relay carries its organization mail. */
export type EmailRelayMode = 'off' | 'verified_sender' | 'on'

/** Settings > E-mail: the organization relay mode (GET/PUT /admin/settings/email-relay). */
export interface EmailRelaySettings extends SettingChange {
  mode: EmailRelayMode
  /** console or default */
  source: string
  default: EmailRelayMode
  env_var: string
  version: number
}

/** Settings > CAPTCHA: the Turnstile keys; the secret is never returned. */
export interface CaptchaSettings extends SettingChange {
  site_key: string
  secret_set: boolean
  source: 'none' | 'console' | 'environment'
  locked_by_environment: boolean
  env_var: string
  version: number
}

/** One social login provider; the client secret is never returned. */
export interface SocialProvider {
  provider: 'google' | 'github' | 'microsoft'
  enabled: boolean
  client_id: string
  secret_set: boolean
  /** The exact callback address to register at the provider. */
  redirect_uri: string
  /** Custom scopes; empty means the provider's defaults. */
  scopes: string[]
  default_scopes: string[]
  source: 'none' | 'console' | 'environment'
  locked_by_environment: boolean
  env_var: string
  /** Sign-in with the provider is offered right now. */
  active: boolean
  /** The stored secret does not decrypt: the provider is off until replaced. */
  undecryptable: boolean
}

/** Settings > Social login. */
export interface SocialLoginSettings extends SettingChange {
  providers: SocialProvider[]
  /** OAUTH_ENABLED on the server; false switches every provider off. */
  master_enabled: boolean
  javascript_origin: string
  /** Who may create an account by public sign-up. */
  signup_accounts: 'closed' | 'domain' | 'open'
  version: number
}

export type SocialCheckResult =
  'valid' | 'invalid' | 'redirect_mismatch' | 'unreachable' | 'unknown'

/** The deployment region, set once before the first organization. */
export interface RegionSettings extends SettingChange {
  region: string
  source: 'none' | 'console' | 'environment'
  locked_by_environment: boolean
  env_var: string
  settable: boolean
}

/** The default storage quota of organizations (0: no quota). */
export interface StorageQuotaSettings extends SettingChange {
  default_mb: number
  source: 'console' | 'environment'
  env_var: string
  environment_mb: number
  max_mb: number
  version: number
}

/** Where CISA KEV and EPSS come from, and how the signed release is doing. */
export interface ThreatSourceSettings extends SettingChange {
  source: 'direct' | 'bundle'
  direct_fetch: 'auto' | 'off'
  stored: boolean
  version: number
  feeds: {
    source: 'kev' | 'epss'
    delivered_via?: 'bundle' | 'direct'
    data_as_of?: string
    bundle_fetched_at?: string
    bundle_fresh: boolean
    bundle_error?: string
  }[]
}

/** Settings > Alerts: the alert webhook; address and secret never returned. */
export interface AlertWebhookSettings extends SettingChange {
  enabled: boolean
  url_set: boolean
  url_host?: string
  secret_set: boolean
  version: number
}

/** Settings > AI provider: the platform AI provider; the key is never returned. */
export interface PlatformAISettings extends SettingChange {
  enabled: boolean
  provider: string
  model: string
  base_url: string
  allow_private: boolean
  allowed_models: string[]
  allow_org_provider: boolean
  org_policy_version: number
  key_set: boolean
  locked_by_environment: boolean
  providers: string[]
  version: number
}

/** A built-in platform role (RFC-134). */
export interface PlatformRoleInfo {
  key: string
  name: string
  description: string
  /** Base roles follow the administrator's tier; one per administrator. */
  base: boolean
  tier: AdminRole
  permissions: string[]
  holders: number
}

/** The platform permission catalog and built-in roles. */
export interface PlatformRolesCatalog {
  roles: PlatformRoleInfo[]
  permissions: { key: string; baseline: boolean; description: string }[]
  named_owners: number
  owners_warning: boolean
}

/** One administrator's platform roles. */
export interface PlatformRoleAssignment {
  admin_id: string
  email: string
  name: string
  active: boolean
  break_glass: boolean
  roles: string[]
}
