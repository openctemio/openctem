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
  /** Empty for a read-only administrator (personal data); see owner_count. */
  owner_emails: string[]
  owner_count: number
  saml_enabled: boolean
  active_identity_providers: number
  verified_domains: number
  sso_enforced: boolean
  /** At least one limit or module deny is set for the organization. */
  limits_apply: boolean
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
}

/** The pair (target type, asset type) cannot change after creation. */
export interface UpdateTargetMappingInput {
  priority?: number
  is_active?: boolean
  description?: string
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
}

export interface PlatformUserDetail extends PlatformUser {
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
  'revoke-sessions' | 'unlock' | 'password-reset' | 'verification-emails'

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
export interface ThreatIntelFeed {
  source: string
  enabled: boolean
  last_sync_at?: string
  last_sync_status: string
  last_error?: string
  records_synced: number
  next_sync_at?: string
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
  | 'http_status'
  | 'too_large'
  | 'invalid'
  | 'rollback'
  | 'conflict'
  | 'expired'
  | 'no_key'

/** GET /admin/version-check/: what the release feed says about this instance. */
export interface VersionCheckStatus {
  enabled: boolean
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
