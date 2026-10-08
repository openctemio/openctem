/**
 * API Endpoints
 *
 * Centralized API endpoint definitions for OpenCTEM
 * Type-safe URL builders for backend API
 */

import { buildQueryString } from './client'
import type { SearchFilters, UserListFilters } from './types'

// ============================================
// BASE ENDPOINTS
// ============================================

/**
 * API base paths
 */
export const API_BASE = {
  AUTH: '/api/v1/auth',
  USERS: '/api/v1/users',
  TENANTS: '/api/v1/tenants',
  INVITATIONS: '/api/v1/invitations',
  ASSETS: '/api/v1/assets',
  VULNERABILITIES: '/api/v1/vulnerabilities',
  DASHBOARD: '/api/v1/dashboard',
  AUDIT_LOGS: '/api/v1/audit-logs',
  SENSORS: '/api/v1/sensors',
  COMMANDS: '/api/v1/commands',
  SCAN_ZONES: '/api/v1/scan-zones',
  SCAN_PROFILES: '/api/v1/scan-profiles',
  SCANNER_TEMPLATES: '/api/v1/scanner-templates',
  TEMPLATE_SOURCES: '/api/v1/template-sources',
  TOOLS: '/api/v1/tools',
  TOOL_CATEGORIES: '/api/v1/tool-categories',
  CAPABILITIES: '/api/v1/capabilities',
  SCANS: '/api/v1/scans',
  EXPOSURES: '/api/v1/exposures',
  THREAT_INTEL: '/api/v1/threat-intel',
  PLATFORM: '/api/v1/platform',
} as const

// ============================================
// AUTH ENDPOINTS
// ============================================

/**
 * Authentication endpoints
 */
export const authEndpoints = {
  /**
   * Get auth provider info
   */
  info: () => `${API_BASE.AUTH}/info`,

  /**
   * Refresh access token
   */
  refresh: () => `${API_BASE.AUTH}/refresh`,

  /**
   * Exchange refresh token for tenant-scoped access token
   */
  token: () => `${API_BASE.AUTH}/token`,

  /**
   * Logout
   */
  logout: () => `${API_BASE.AUTH}/logout`,

  // ============================================
  // LOCAL AUTH
  // ============================================

  /**
   * Register new user (local auth)
   */
  register: () => `${API_BASE.AUTH}/register`,

  /** Email-first sign-in: where does this email sign in? (email in the body) */
  discover: () => `${API_BASE.AUTH}/discover`,

  /**
   * Login with email/password (local auth)
   */
  login: () => `${API_BASE.AUTH}/login`,

  /**
   * Verify email with token
   */
  verifyEmail: (token: string) => `${API_BASE.AUTH}/verify-email?token=${token}`,

  /**
   * Request password reset
   */
  forgotPassword: () => `${API_BASE.AUTH}/forgot-password`,

  /**
   * Reset password with token
   */
  resetPassword: () => `${API_BASE.AUTH}/reset-password`,

  /**
   * Create first team for new user (uses refresh token)
   */
  createFirstTeam: () => `${API_BASE.AUTH}/create-first-team`,

  /**
   * Second login step: verify a TOTP or recovery code against the challenge
   * a password login returned (mfa_token). Public, rate limited.
   */
  mfaVerify: () => `${API_BASE.AUTH}/mfa/verify`,

  /**
   * Required 2FA enrollment during login (organization policy): get a secret.
   */
  mfaEnrollStart: () => `${API_BASE.AUTH}/mfa/enroll/start`,

  /**
   * Required 2FA enrollment during login: confirm with a code and sign in.
   */
  mfaEnrollConfirm: () => `${API_BASE.AUTH}/mfa/enroll/confirm`,

  // ============================================
  // SOCIAL/OAUTH AUTH
  // ============================================

  /**
   * Get OAuth authorization URL for a provider
   * @param provider - OAuth provider (google, github, microsoft)
   */
  oauthAuthorize: (provider: string) => `${API_BASE.AUTH}/oauth/${provider}/authorize`,

  /**
   * OAuth callback endpoint (handled by backend, redirects to frontend)
   * @param provider - OAuth provider (google, github, microsoft)
   */
  oauthCallback: (provider: string) => `${API_BASE.AUTH}/oauth/${provider}/callback`,

  // Per-tenant SSO endpoints (public)
  /**
   * List active SSO providers for a tenant
   * @param orgSlug - Tenant slug (org identifier)
   */
  ssoProviders: (orgSlug: string) =>
    `${API_BASE.AUTH}/sso/providers?org=${encodeURIComponent(orgSlug)}`,

  /**
   * Get SSO authorization URL
   * @param provider - SSO provider (entra_id, okta, google_workspace)
   */
  ssoAuthorize: (provider: string) => `${API_BASE.AUTH}/sso/${provider}/authorize`,

  /**
   * SSO callback endpoint
   * @param provider - SSO provider (entra_id, okta, google_workspace)
   */
  ssoCallback: (provider: string) => `${API_BASE.AUTH}/sso/${provider}/callback`,
} as const

// ============================================
// USER ENDPOINTS
// ============================================

/**
 * User endpoints
 */
export const userEndpoints = {
  // ============================================
  // CURRENT USER (Profile)
  // ============================================

  /**
   * Get current user's profile
   */
  me: () => `${API_BASE.USERS}/me`,

  /**
   * Update current user's profile
   */
  updateMe: () => `${API_BASE.USERS}/me`,

  /**
   * Update current user's preferences
   */
  updatePreferences: () => `${API_BASE.USERS}/me/preferences`,

  /**
   * Get current user's tenants/teams
   */
  myTenants: () => `${API_BASE.USERS}/me/tenants`,

  // ============================================
  // SESSION MANAGEMENT (Local Auth)
  // ============================================

  /**
   * Change password (authenticated user)
   */
  changePassword: () => `${API_BASE.USERS}/me/change-password`,

  /**
   * List active sessions
   */
  sessions: () => `${API_BASE.USERS}/me/sessions`,

  /**
   * Revoke all sessions except current
   */
  revokeAllSessions: () => `${API_BASE.USERS}/me/sessions`,

  /**
   * Revoke specific session
   */
  revokeSession: (sessionId: string) => `${API_BASE.USERS}/me/sessions/${sessionId}`,

  /**
   * Two-factor authentication (signed-in user)
   */
  twoFactor: () => `${API_BASE.USERS}/me/2fa`,
  twoFactorSetup: () => `${API_BASE.USERS}/me/2fa/setup`,
  twoFactorEnable: () => `${API_BASE.USERS}/me/2fa/enable`,
  twoFactorDisable: () => `${API_BASE.USERS}/me/2fa/disable`,
  twoFactorRecoveryCodes: () => `${API_BASE.USERS}/me/2fa/recovery-codes`,

  // ============================================
  // USER MANAGEMENT (Admin)
  // ============================================

  /**
   * List users with filters (admin)
   */
  list: (filters?: UserListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.USERS}${queryString}`
  },

  /**
   * Get single user by ID (admin)
   */
  get: (userId: string) => `${API_BASE.USERS}/${userId}`,

  /**
   * Create new user (admin)
   */
  create: () => API_BASE.USERS,

  /**
   * Update user by ID (admin)
   */
  update: (userId: string) => `${API_BASE.USERS}/${userId}`,

  /**
   * Delete user by ID (admin)
   */
  delete: (userId: string) => `${API_BASE.USERS}/${userId}`,
} as const

// ============================================
// TENANT ENDPOINTS (Teams)
// ============================================

/**
 * Tenant endpoints (API uses "tenant", UI displays "Team")
 */
export const tenantEndpoints = {
  /**
   * List user's tenants/teams
   */
  list: (filters?: SearchFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.TENANTS}${queryString}`
  },

  /**
   * Create a new tenant/team
   */
  create: () => API_BASE.TENANTS,

  /**
   * Get tenant by ID or slug
   */
  get: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}`,

  /**
   * Update tenant
   */
  update: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}`,

  /**
   * Delete tenant
   */
  delete: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}`,

  // ============================================
  // MEMBER MANAGEMENT
  // ============================================

  /**
   * List tenant members
   */
  members: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}/members`,

  /**
   * Get member statistics
   */
  memberStats: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}/members/stats`,

  /**
   * Add member to tenant
   */
  addMember: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}/members`,

  /**
   * Update member (alias for updateMemberRole)
   */
  updateMember: (tenantIdOrSlug: string, memberId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/members/${memberId}`,

  /**
   * Update member role
   */
  updateMemberRole: (tenantIdOrSlug: string, memberId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/members/${memberId}`,

  /**
   * Create a user account directly (POST, owner/admin) — no self-registration
   */
  createUser: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}/users`,

  /**
   * Issue a fresh one-time setup link for a member still pending setup (POST)
   */
  userSetupLink: (tenantIdOrSlug: string, userId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/users/${userId}/setup-link`,

  // ============================================
  // INVITATION MANAGEMENT
  // ============================================

  /**
   * List tenant invitations
   */
  invitations: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}/invitations`,

  /**
   * Create invitation
   */
  createInvitation: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}/invitations`,

  /**
   * Delete invitation
   */
  deleteInvitation: (tenantIdOrSlug: string, invitationId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/invitations/${invitationId}`,

  /**
   * Resend invitation email (POST) — re-queues the email without
   * changing the token, expiry, or any other metadata.
   */
  resendInvitation: (tenantIdOrSlug: string, invitationId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/invitations/${invitationId}/resend`,

  /**
   * Suspend a member (POST) — revokes access, preserves membership row
   */
  suspendMember: (tenantIdOrSlug: string, memberId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/members/${memberId}/suspend`,

  /**
   * Reactivate a suspended member (POST) — restores access
   */
  reactivateMember: (tenantIdOrSlug: string, memberId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/members/${memberId}/reactivate`,

  /**
   * Reset a member's two-factor authentication (POST) — owner/admin
   */
  resetMemberMfa: (memberId: string) => `/api/v1/organization/members/${memberId}/mfa`,

  /**
   * What a member holds and owns (GET, owner/admin) — member lifecycle, RFC-050
   */
  memberAccessReport: (memberId: string) =>
    `/api/v1/organization/members/${memberId}/access-report`,

  /**
   * When an external member's access ends (PATCH, owner/admin) — RFC-058
   */
  memberAccess: (memberId: string) => `/api/v1/organization/members/${memberId}/access`,

  /**
   * Trusted organizations (GET owner/admin; changes owner + step-up) — RFC-058
   */
  orgTrusts: () => '/api/v1/organization/trusts',
  orgTrust: (trustId: string) => `/api/v1/organization/trusts/${trustId}`,
  approveOrgTrust: (trustId: string) => `/api/v1/organization/trusts/${trustId}/approve`,

  /**
   * Offboard a member with mandatory reassignment (POST, owner/admin)
   */
  offboardMember: (memberId: string) => `/api/v1/organization/members/${memberId}/offboard`,

  /**
   * Erase an offboarded person's name and email (POST, owner only)
   */
  eraseMember: (memberId: string) => `/api/v1/organization/members/${memberId}/erase`,

  // ============================================
  // SETTINGS MANAGEMENT
  // ============================================

  /**
   * Get tenant settings
   */
  settings: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings`,

  /**
   * Update general settings
   */
  updateGeneralSettings: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/general`,

  /**
   * Update security settings
   */
  updateSecuritySettings: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/security`,

  /**
   * Update API settings
   */

  /**
   * Update branding settings
   */
  updateBrandingSettings: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/branding`,

  /**
   * Risk scoring settings
   */
  riskScoringSettings: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/risk-scoring`,

  /**
   * Preview risk scoring changes
   */
  riskScoringPreview: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/risk-scoring/preview`,

  /**
   * Recalculate risk scores
   */
  riskScoringRecalculate: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/risk-scoring/recalculate`,

  /**
   * Risk scoring presets
   */
  riskScoringPresets: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/risk-scoring/presets`,

  /**
   * Module management
   */
  modules: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/modules`,

  /**
   * Reset modules to defaults
   */
  modulesReset: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/modules/reset`,

  /**
   * Platform-wide module dependency graph (static spec).
   * Returns flat edge list the UI uses to render dependency badges
   * and cascading-confirm dialogs on the Settings → Modules page.
   */
  modulesGraph: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/modules/graph`,

  /**
   * Dry-run of a module toggle. POST with the same body as the PATCH
   * endpoint; returns blockers + warnings + required without writing.
   * UI calls this before each toggle commit to drive the confirm modal.
   */
  modulesValidate: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/modules/validate`,

  /**
   * Curated module presets (VM Essentials, ASM, Bug Bounty, CTEM Full…).
   * GET returns the static catalogue; preview returns a dry-run diff;
   * apply writes the diff into tenant_modules.
   */
  modulesPresets: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/modules/presets`,
  /**
   * Tenantless preset catalogue — same payload, used by the team
   * creation form BEFORE the tenant exists. No auth variation: the
   * list is product-spec, not tenant-specific.
   */
  modulesPresetsPublic: () => `/api/v1/module-presets/`,
  modulesPresetPreview: (tenantIdOrSlug: string, presetId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/modules/presets/${presetId}/preview`,
  modulesPresetApply: (tenantIdOrSlug: string, presetId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/modules/presets/${presetId}/apply`,
  /**
   * Product-bundle subscription. GET returns the current subscription +
   * catalog; POST replaces the subscription (live-resolved module set).
   */
  modulesBundles: (tenantIdOrSlug: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/settings/modules/bundles`,
} as const

// ============================================
// INVITATION ENDPOINTS (Public)
// ============================================

/**
 * Invitation endpoints for accepting invitations. The token is a bearer
 * credential: every call sends it in the JSON body ({ token }), never in the
 * URL (RFC-041).
 */
export const invitationEndpoints = {
  /** What a token grants, readable before sign-in (public). */
  lookup: () => `${API_BASE.INVITATIONS}/lookup`,

  /** Accept as the signed-in, invited email. */
  accept: () => `${API_BASE.INVITATIONS}/accept`,

  /** Accept with the refresh token, for a user who has no organization yet. */
  acceptWithRefresh: () => `${API_BASE.INVITATIONS}/accept-with-refresh`,

  /** Decline (public: holding the token is the authorization). */
  decline: () => `${API_BASE.INVITATIONS}/decline`,
} as const

// ============================================
// ASSET ENDPOINTS (Global)
// ============================================

/**
 * Asset endpoints (global resources)
 * Supports unified asset types including repositories (git repos)
 */
export const assetEndpoints = {
  // ============================================
  // BASIC CRUD
  // ============================================

  /**
   * List assets
   */
  list: (filters?: SearchFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.ASSETS}${queryString}`
  },

  /**
   * Get asset by ID
   */
  get: (assetId: string) => `${API_BASE.ASSETS}/${assetId}`,

  /**
   * Create asset
   */
  create: () => API_BASE.ASSETS,

  /**
   * Update asset
   */
  update: (assetId: string) => `${API_BASE.ASSETS}/${assetId}`,

  /**
   * Delete asset
   */
  delete: (assetId: string) => `${API_BASE.ASSETS}/${assetId}`,

  // ============================================
  // REPOSITORY EXTENSION
  // ============================================

  /**
   * Get asset with repository extension (full data)
   */
  getFull: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/full`,

  /**
   * Get repository extension for an asset
   */
  getRepository: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/repository`,

  /**
   * Create repository asset (creates asset + repository extension)
   */
  createRepository: () => `${API_BASE.ASSETS}/repository`,

  /**
   * Update repository extension
   */
  updateRepository: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/repository`,

  // ============================================
  // STATUS OPERATIONS
  // ============================================

  /**
   * Activate asset (set status to active)
   */
  activate: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/activate`,

  /**
   * Deactivate asset (set status to inactive)
   */
  deactivate: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/deactivate`,

  /**
   * Archive asset (set status to archived)
   */
  archive: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/archive`,

  // ============================================
  // STATISTICS
  // ============================================

  /**
   * Get asset statistics (comprehensive stats with all breakdowns)
   * Includes: by_type, by_status, by_criticality, by_scope, by_exposure,
   * high_risk_count, findings_total, risk_score_avg
   */
  stats: () => `${API_BASE.ASSETS}/stats`,

  /**
   * Get property facets for dynamic filtering
   * Returns distinct property keys and their values for the given asset types
   */
  facets: () => `${API_BASE.ASSETS}/facets`,

  // ============================================
  // ASSET OWNERS
  // ============================================

  /**
   * List owners of an asset
   */
  listOwners: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/owners`,

  /**
   * Add an owner to an asset
   */
  addOwner: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/owners`,

  /**
   * Update an owner's type
   */
  updateOwner: (assetId: string, ownerId: string) =>
    `${API_BASE.ASSETS}/${assetId}/owners/${ownerId}`,

  /**
   * Remove an owner from an asset
   */
  removeOwner: (assetId: string, ownerId: string) =>
    `${API_BASE.ASSETS}/${assetId}/owners/${ownerId}`,

  /**
   * Explicit per-user data-scope grants. Being an owner gives no access;
   * groups and these grants do (team:groups:read / team:groups:write).
   */
  listAccessGrants: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/access-grants`,
  createAccessGrant: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/access-grants`,
  deleteAccessGrant: (assetId: string, grantId: string) =>
    `${API_BASE.ASSETS}/${assetId}/access-grants/${grantId}`,

  // ============================================
  // ASSET RELATIONSHIPS
  // ============================================

  /**
   * List relationships for an asset
   */
  listRelationships: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/relationships`,

  /**
   * Create a new relationship for an asset (POST)
   * The {id} in the path is the source asset; backend also requires
   * source_asset_id in the body and rejects mismatches.
   */
  createRelationship: (assetId: string) => `${API_BASE.ASSETS}/${assetId}/relationships`,

  /**
   * Update a relationship by its own ID (PUT)
   */
  updateRelationship: (relationshipId: string) => `/api/v1/relationships/${relationshipId}`,

  /**
   * Delete a relationship by its own ID (DELETE)
   */
  deleteRelationship: (relationshipId: string) => `/api/v1/relationships/${relationshipId}`,
} as const

// ============================================
// COMPONENT ENDPOINTS (Tenant-scoped)
// ============================================

/**
 * Component endpoints (tenant-scoped dependencies/packages)
 */
export const componentEndpoints = {
  /**
   * List components in tenant
   */
  list: (tenantIdOrSlug: string, filters?: SearchFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.TENANTS}/${tenantIdOrSlug}/components${queryString}`
  },

  /**
   * Get component by ID
   */
  get: (tenantIdOrSlug: string, componentId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/components/${componentId}`,

  /**
   * Create component (member+ role)
   */
  create: (tenantIdOrSlug: string) => `${API_BASE.TENANTS}/${tenantIdOrSlug}/components`,

  /**
   * Update component (member+ role)
   */
  update: (tenantIdOrSlug: string, componentId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/components/${componentId}`,

  /**
   * Delete component (admin+ role)
   */
  delete: (tenantIdOrSlug: string, componentId: string) =>
    `${API_BASE.TENANTS}/${tenantIdOrSlug}/components/${componentId}`,

  /**
   * List components by project
   */
  listByProject: (tenantIdOrSlug: string, projectId: string, filters?: SearchFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.TENANTS}/${tenantIdOrSlug}/projects/${projectId}/components${queryString}`
  },
} as const

// ============================================
// VULNERABILITY ENDPOINTS (Global CVE database)
// ============================================

/**
 * Vulnerability endpoints (global CVE database)
 */
export const vulnerabilityEndpoints = {
  /**
   * List vulnerabilities
   */
  list: (filters?: SearchFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.VULNERABILITIES}${queryString}`
  },

  /**
   * Get vulnerability by ID
   */
  get: (vulnId: string) => `${API_BASE.VULNERABILITIES}/${vulnId}`,

  /**
   * Get vulnerability by CVE ID
   */
  getByCVE: (cveId: string) => `${API_BASE.VULNERABILITIES}/cve/${cveId}`,

  /**
   * Create vulnerability (admin only)
   */
  create: () => API_BASE.VULNERABILITIES,

  /**
   * Update vulnerability (admin only)
   */
  update: (vulnId: string) => `${API_BASE.VULNERABILITIES}/${vulnId}`,

  /**
   * Delete vulnerability (admin only)
   */
  delete: (vulnId: string) => `${API_BASE.VULNERABILITIES}/${vulnId}`,
} as const

// ============================================
// FINDING ENDPOINTS (Tenant from JWT token)
// ============================================

import type { FindingListFilters } from './finding-types'

/**
 * Finding endpoints (tenant extracted from JWT, not URL path)
 */
export const findingEndpoints = {
  /**
   * List findings (tenant from JWT)
   */
  list: (filters?: FindingListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `/api/v1/findings${queryString}`
  },

  /**
   * Get finding by ID
   */
  get: (findingId: string) => `/api/v1/findings/${findingId}`,

  /**
   * Create finding
   */
  create: () => '/api/v1/findings',

  /**
   * Update finding status
   */
  updateStatus: (findingId: string) => `/api/v1/findings/${findingId}/status`,

  /**
   * Delete finding
   */
  delete: (findingId: string) => `/api/v1/findings/${findingId}`,

  /**
   * List findings for an asset
   */
  listByAsset: (assetId: string, filters?: FindingListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `/api/v1/assets/${assetId}/findings${queryString}`
  },

  /**
   * List comments for a finding
   */
  comments: (findingId: string) => `/api/v1/findings/${findingId}/comments`,

  /**
   * Add comment to a finding
   */
  addComment: (findingId: string) => `/api/v1/findings/${findingId}/comments`,

  /**
   * Update comment
   */
  updateComment: (findingId: string, commentId: string) =>
    `/api/v1/findings/${findingId}/comments/${commentId}`,

  /**
   * Delete comment
   */
  deleteComment: (findingId: string, commentId: string) =>
    `/api/v1/findings/${findingId}/comments/${commentId}`,
} as const

// ============================================
// DASHBOARD ENDPOINTS
// ============================================

/**
 * Dashboard endpoints for aggregated statistics
 */
export const dashboardEndpoints = {
  /**
   * Get tenant-scoped dashboard stats
   */
  stats: () => `${API_BASE.DASHBOARD}/stats`,
  /**
   * Executive summary metrics for the trailing `days` window (JSON).
   */
  executiveSummary: (days?: number) =>
    `${API_BASE.DASHBOARD}/executive-summary${days ? buildQueryString({ days }) : ''}`,
  /**
   * Executive summary export (server-rendered). `format=csv` streams a CSV
   * download; default is JSON.
   */
  executiveSummaryExport: (days: number, format: 'csv' | 'json' = 'csv') =>
    `${API_BASE.DASHBOARD}/executive-summary/export${buildQueryString({ days, format })}`,
} as const

/**
 * Report schedule endpoints. Schedules email a finding-summary digest to
 * recipients on a cron cadence (there is no downloadable artifact store).
 */
export const reportsEndpoints = {
  schedules: () => `/api/v1/reports/schedules`,
  schedule: (id: string) => `/api/v1/reports/schedules/${id}`,
  toggle: (id: string) => `/api/v1/reports/schedules/${id}/toggle`,
} as const

// ============================================
// UTILITIES
// ============================================

/**
 * Build paginated endpoint
 */
export function buildPaginatedEndpoint(
  baseUrl: string,
  page: number = 1,
  pageSize: number = 10
): string {
  return `${baseUrl}${buildQueryString({ page, pageSize })}`
}

/**
 * Build search endpoint
 */
export function buildSearchEndpoint(
  baseUrl: string,
  query: string,
  filters?: Record<string, unknown>
): string {
  return `${baseUrl}${buildQueryString({ query, ...filters })}`
}

/**
 * Build sort endpoint
 */
export function buildSortEndpoint(
  baseUrl: string,
  sortBy: string,
  sortOrder: 'asc' | 'desc' = 'asc'
): string {
  return `${baseUrl}${buildQueryString({ sortBy, sortOrder })}`
}

// ============================================
// AUDIT LOG ENDPOINTS
// ============================================

/**
 * Audit log endpoints (tenant from JWT token, not URL path)
 * Backend uses /api/v1/audit-logs with tenant extracted from JWT
 */
export const auditLogEndpoints = {
  /**
   * List audit logs with optional filters
   */
  list: (filters?: SearchFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.AUDIT_LOGS}${queryString}`
  },

  /**
   * Get audit log statistics
   */
  stats: () => `${API_BASE.AUDIT_LOGS}/stats`,

  /**
   * Get single audit log by ID
   */
  get: (logId: string) => `${API_BASE.AUDIT_LOGS}/${logId}`,

  /**
   * Get resource audit history
   */
  resourceHistory: (resourceType: string, resourceId: string) =>
    `${API_BASE.AUDIT_LOGS}/resource/${resourceType}/${resourceId}`,

  /**
   * Get user activity
   */
  userActivity: (userId: string) => `${API_BASE.AUDIT_LOGS}/user/${userId}`,
} as const

// ============================================
// SENSOR ENDPOINTS
// ============================================

import type { SensorActivityQuery, SensorListFilters } from './sensor-types'

/**
 * Sensor endpoints for managing sensors (runners, workers, collectors, sensors)
 */
export const sensorEndpoints = {
  /**
   * List sensors with optional filters
   */
  list: (filters?: SensorListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.SENSORS}${queryString}`
  },

  /**
   * Get sensor by ID
   */
  get: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}`,

  /**
   * Create a new sensor
   */
  create: () => API_BASE.SENSORS,

  /**
   * Update sensor
   */
  update: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}`,

  /**
   * Delete sensor
   */
  delete: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}`,

  /**
   * Regenerate sensor API key
   */
  regenerateKey: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}/regenerate-key`,

  /**
   * Get sensor statistics
   */
  stats: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}/stats`,

  /**
   * Tenant-wide sensor stats (status/health/type/mode breakdowns).
   * SQL-aggregated server-side; replaces client-side .filter().length.
   */
  tenantStats: () => `${API_BASE.SENSORS}/stats`,

  /**
   * Activate sensor (set status to active)
   */
  activate: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}/activate`,

  /**
   * Deactivate sensor (set status to disabled)
   */
  deactivate: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}/deactivate`,

  /**
   * Revoke sensor (permanently revoke access)
   */
  revoke: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}/revoke`,

  /**
   * Get available capabilities for tenant
   * Returns unique capability names from all sensors (tenant + platform) accessible to the tenant
   * @param includePlatform - Whether to include platform sensors (default: true)
   */
  availableCapabilities: (includePlatform: boolean = true) =>
    `${API_BASE.SENSORS}/available-capabilities?include_platform=${includePlatform}`,

  /**
   * The jobs (commands) dispatched to one sensor, newest first
   * (GET /commands?sensor_id=, needs sensors:commands:read).
   */
  commands: (sensorId: string, perPage = 20) =>
    `${API_BASE.COMMANDS}${buildQueryString({ sensor_id: sensorId, per_page: perPage })}`,

  /**
   * A sensor's activity timeline, newest first (sensors:read): connection
   * changes, restarts, upgrades, tool and content changes, jobs and, with
   * audit:read, administrator actions.
   */
  activity: (sensorId: string, query: SensorActivityQuery = {}) =>
    `${API_BASE.SENSORS}/${sensorId}/activity${buildQueryString({
      types: query.types?.length ? query.types.join(',') : undefined,
      cursor: query.cursor,
      limit: query.limit,
    })}`,

  /** The sensor's heartbeat history in 15-minute buckets (RFC-035, sensors:read; at most 24 h). */
  heartbeatHistory: (sensorId: string, hours = 24) =>
    `${API_BASE.SENSORS}/${sensorId}/heartbeat-history${buildQueryString({ hours })}`,

  /** The sensor's current manifest (RFC-033, sensors:read); 404 before the first. */
  manifest: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}/manifest`,

  /** The sensor's manifest versions, most recently current first (RFC-033). */
  manifests: (sensorId: string, limit = 50) =>
    `${API_BASE.SENSORS}/${sensorId}/manifests${buildQueryString({ limit })}`,

  /** The sensor's setup report and its checks (research/26, sensors:read). */
  configReport: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}/config-report`,

  /** The tenant's scanner content policy (RFC-031): GET, PUT with sensors:write. */
  contentPolicy: () => `${API_BASE.SENSORS}/content-policy`,

  /** Ask one sensor to refresh its scanner content now (sensors:write). */
  refreshContent: (sensorId: string) => `${API_BASE.SENSORS}/${sensorId}/content/refresh`,

  /** Ask every sensor that manages content to refresh it (sensors:write). */
  refreshFleetContent: () => `${API_BASE.SENSORS}/content/refresh`,
} as const

// ============================================
// SCAN PROFILE ENDPOINTS
// ============================================

import type { ScanProfileListFilters } from './scan-profile-types'

/**
 * Scan profile endpoints for managing reusable scan configurations
 */
export const scanProfileEndpoints = {
  /**
   * List scan profiles with optional filters
   */
  list: (filters?: ScanProfileListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.SCAN_PROFILES}${queryString}`
  },

  /**
   * Get scan profile by ID
   */
  get: (profileId: string) => `${API_BASE.SCAN_PROFILES}/${profileId}`,

  /**
   * Get default scan profile for tenant
   */
  getDefault: () => `${API_BASE.SCAN_PROFILES}/default`,

  /**
   * Create a new scan profile
   */
  create: () => API_BASE.SCAN_PROFILES,

  /**
   * Update scan profile
   */
  update: (profileId: string) => `${API_BASE.SCAN_PROFILES}/${profileId}`,

  /**
   * Delete scan profile
   */
  delete: (profileId: string) => `${API_BASE.SCAN_PROFILES}/${profileId}`,

  /**
   * Set scan profile as default
   */
  setDefault: (profileId: string) => `${API_BASE.SCAN_PROFILES}/${profileId}/set-default`,

  /**
   * Clone a scan profile
   */
  clone: (profileId: string) => `${API_BASE.SCAN_PROFILES}/${profileId}/clone`,

  /**
   * Update quality gate configuration
   */
  updateQualityGate: (profileId: string) => `${API_BASE.SCAN_PROFILES}/${profileId}/quality-gate`,

  /**
   * Evaluate quality gate against finding counts
   */
  evaluateQualityGate: (profileId: string) =>
    `${API_BASE.SCAN_PROFILES}/${profileId}/evaluate-quality-gate`,
} as const

// ============================================
// SCANNER TEMPLATE ENDPOINTS
// ============================================

import type { ScannerTemplateListFilters } from './scanner-template-types'

/**
 * Scanner template endpoints for managing custom detection rules
 * Supports Nuclei (YAML), Semgrep (YAML), and Betterleaks (TOML) templates
 */
export const scannerTemplateEndpoints = {
  /**
   * List scanner templates with optional filters
   */
  list: (filters?: ScannerTemplateListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.SCANNER_TEMPLATES}${queryString}`
  },

  /**
   * Get scanner template by ID
   */
  get: (templateId: string) => `${API_BASE.SCANNER_TEMPLATES}/${templateId}`,

  /**
   * Create a new scanner template
   */
  create: () => API_BASE.SCANNER_TEMPLATES,

  /**
   * Update scanner template
   */
  update: (templateId: string) => `${API_BASE.SCANNER_TEMPLATES}/${templateId}`,

  /**
   * Delete scanner template
   */
  delete: (templateId: string) => `${API_BASE.SCANNER_TEMPLATES}/${templateId}`,

  /**
   * Validate template content before upload
   */
  validate: () => `${API_BASE.SCANNER_TEMPLATES}/validate`,

  /**
   * Download template content
   */
  download: (templateId: string) => `${API_BASE.SCANNER_TEMPLATES}/${templateId}/download`,

  /**
   * Deprecate template (mark as deprecated)
   */
  deprecate: (templateId: string) => `${API_BASE.SCANNER_TEMPLATES}/${templateId}/deprecate`,

  /**
   * Get template usage and quota information for the tenant
   */
  usage: () => `${API_BASE.SCANNER_TEMPLATES}/usage`,
} as const

// ============================================
// TOOL ENDPOINTS
// ============================================

import type { ToolListFilters } from './tool-types'

/**
 * The organization's view of the tool catalog (api tool-availability.md):
 * platform tools plus its own custom tools, one resource. include= adds its
 * settings, the availability from its sensors and run statistics.
 */
export const toolEndpoints = {
  /** List with filters, sort, pagination and include= */
  list: (filters?: ToolListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.TOOLS}${queryString}`
  },

  /** One tool (platform or own custom) */
  get: (toolId: string) => `${API_BASE.TOOLS}/${toolId}`,

  /** Create a custom tool owned by the organization */
  create: () => API_BASE.TOOLS,

  /** Update / delete one of the organization's custom tools */
  update: (toolId: string) => `${API_BASE.TOOLS}/${toolId}`,
  delete: (toolId: string) => `${API_BASE.TOOLS}/${toolId}`,

  /** PATCH: the organization's switch and config overrides of one tool */
  settings: (toolId: string) => `${API_BASE.TOOLS}/${toolId}/settings`,

  /** PATCH: switch several tools on or off */
  bulkSettings: () => `${API_BASE.TOOLS}/settings`,
} as const

// ============================================
// TOOL CATEGORY ENDPOINTS
// ============================================

import type { ToolCategoryListFilters } from './tool-category-types'

/**
 * Tool categories: platform plus the organization's custom ones. Changes
 * reach only its own custom categories.
 */
export const toolCategoryEndpoints = {
  list: (filters?: ToolCategoryListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.TOOL_CATEGORIES}${queryString}`
  },
  get: (categoryId: string) => `${API_BASE.TOOL_CATEGORIES}/${categoryId}`,
  create: () => API_BASE.TOOL_CATEGORIES,
  update: (categoryId: string) => `${API_BASE.TOOL_CATEGORIES}/${categoryId}`,
  delete: (categoryId: string) => `${API_BASE.TOOL_CATEGORIES}/${categoryId}`,
} as const

// ============================================
// CAPABILITY ENDPOINTS
// ============================================

import type { CapabilityListFilters } from './capability-types'

/**
 * Capability endpoints: one collection, platform and the organization's custom capabilities
 */
export const capabilityEndpoints = {
  /**
   * List capabilities: the platform ones and the organization's own custom
   * ones (source=platform|custom, category, q, include=usage, page, per_page).
   */
  list: (filters?: CapabilityListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.CAPABILITIES}${queryString}`
  },

  /**
   * Get one capability; include=usage adds which tools and sensors have it.
   */
  get: (capabilityId: string, include?: 'usage') =>
    `${API_BASE.CAPABILITIES}/${capabilityId}${include ? `?include=${include}` : ''}`,

  /**
   * The categories in use (security, recon, analysis, ...)
   */
  categories: () => `${API_BASE.CAPABILITIES}/categories`,

  /**
   * Create a custom capability (owner/admin)
   */
  create: () => API_BASE.CAPABILITIES,

  /**
   * Update one of the organization's custom capabilities
   */
  update: (capabilityId: string) => `${API_BASE.CAPABILITIES}/${capabilityId}`,

  /**
   * Delete one of the organization's custom capabilities
   * @param force - Force delete even if capability is in use
   */
  delete: (capabilityId: string, force?: boolean) =>
    `${API_BASE.CAPABILITIES}/${capabilityId}${force ? '?force=true' : ''}`,
} as const

// ============================================
// SCAN_WORKFLOW ENDPOINTS
// ============================================

import type { ScanWorkflowListFilters, ScanRunListFilters } from './scan-workflow-types'
import type { WorkflowListFilters, WorkflowRunListFilters } from './workflow-types'

/**
 * Scan workflow endpoints: the graph of steps a scan runs
 * (GET/POST /api/v1/scan-workflows, scans:workflows:*).
 */
export const scanWorkflowEndpoints = {
  /**
   * List workflows with optional filters
   */
  list: (filters?: ScanWorkflowListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `/api/v1/scan-workflows${queryString}`
  },

  /**
   * Get workflow by ID
   */
  get: (workflowId: string) => `/api/v1/scan-workflows/${workflowId}`,

  /**
   * Create a new workflow
   */
  create: () => '/api/v1/scan-workflows',

  /**
   * Update workflow
   */
  update: (workflowId: string) => `/api/v1/scan-workflows/${workflowId}`,

  /**
   * Delete workflow
   */
  delete: (workflowId: string) => `/api/v1/scan-workflows/${workflowId}`,

  /**
   * Activate workflow
   */
  activate: (workflowId: string) => `/api/v1/scan-workflows/${workflowId}/activate`,

  /**
   * Deactivate workflow
   */
  deactivate: (workflowId: string) => `/api/v1/scan-workflows/${workflowId}/deactivate`,

  /**
   * Clone workflow
   */
  clone: (workflowId: string) => `/api/v1/scan-workflows/${workflowId}/clone`,

  /**
   * Add step to workflow
   */
  addStep: (workflowId: string) => `/api/v1/scan-workflows/${workflowId}/steps`,

  /**
   * Update step
   */
  updateStep: (workflowId: string, stepId: string) =>
    `/api/v1/scan-workflows/${workflowId}/steps/${stepId}`,

  /**
   * Delete step
   */
  deleteStep: (workflowId: string, stepId: string) =>
    `/api/v1/scan-workflows/${workflowId}/steps/${stepId}`,

  /**
   * Check a draft workflow's steps as a workflow graph (stores nothing)
   */
  verify: () => '/api/v1/scan-workflows/verify',

  /**
   * The scan capability catalog: contracts, port types and adapters
   */
  capabilities: () => '/api/v1/scans/stages',
} as const

/**
 * Scan run endpoints: one execution of a scan (scans:read)
 */
/**
 * Scan zone endpoints (RFC-023): tenant from the JWT.
 */
export const scanZoneEndpoints = {
  list: () => API_BASE.SCAN_ZONES,
  coverage: () => `${API_BASE.SCAN_ZONES}/coverage`,
  preview: () => `${API_BASE.SCAN_ZONES}/preview`,
  get: (zoneId: string) => `${API_BASE.SCAN_ZONES}/${zoneId}`,
  create: () => API_BASE.SCAN_ZONES,
  update: (zoneId: string) => `${API_BASE.SCAN_ZONES}/${zoneId}`,
  delete: (zoneId: string) => `${API_BASE.SCAN_ZONES}/${zoneId}`,
  sensor: (zoneId: string, sensorId: string) =>
    `${API_BASE.SCAN_ZONES}/${zoneId}/sensors/${sensorId}`,
} as const

export const scanRunEndpoints = {
  /**
   * List workflow runs with optional filters
   */
  list: (filters?: ScanRunListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `/api/v1/scan-runs${queryString}`
  },

  /**
   * Get workflow run by ID
   */
  get: (runId: string) => `/api/v1/scan-runs/${runId}`,

  /**
   * Cancel a running workflow
   */
  cancel: (runId: string) => `/api/v1/scan-runs/${runId}/cancel`,

  /**
   * How each stage of a run was planned (counts by reason; research/27).
   */
  stages: (runId: string) => `/api/v1/scan-runs/${encodeURIComponent(runId)}/stages`,

  /** A run's timeline: every change of its tasks, oldest first (research/62 P0-4). */
  events: (runId: string) => `/api/v1/scan-runs/${encodeURIComponent(runId)}/events`,
  /** The run drawn on its workflow version: step states, chunks, outputs. */
  map: (runId: string) => `/api/v1/scan-runs/${encodeURIComponent(runId)}/map`,

  /**
   * One cursor page of a run's tasks (the run read embeds the first page and
   * its tasks_next_cursor).
   */
  tasks: (runId: string, cursor?: string, perPage?: number) => {
    const params = new URLSearchParams()
    if (cursor) params.set('cursor', cursor)
    if (perPage) params.set('per_page', String(perPage))
    const qs = params.toString()
    return `/api/v1/scan-runs/${encodeURIComponent(runId)}/tasks${qs ? `?${qs}` : ''}`
  },

  /**
   * The log lines a task's sensor sent (kept 14 days).
   */
  taskLogs: (runId: string, taskId: string) =>
    `/api/v1/scan-runs/${encodeURIComponent(runId)}/tasks/${encodeURIComponent(taskId)}/logs`,
} as const

/**
 * Scan Management stats endpoint
 */
export const scanManagementEndpoints = {
  /**
   * Get overview stats (workflows, scans, jobs)
   */
  stats: () => '/api/v1/scans/overview-stats',

  /**
   * Quick scan
   */
  quickScan: () => '/api/v1/scans/quick',
} as const

// ============================================
// WORKFLOW ENDPOINTS (Automation Workflows)
// ============================================

/**
 * Workflow endpoints for managing automation workflows
 * Workflows are event-driven automation workflows with visual graph builder
 */
export const workflowEndpoints = {
  /**
   * List workflows with optional filters
   */
  list: (filters?: WorkflowListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `/api/v1/workflows${queryString}`
  },

  /**
   * Get workflow by ID
   */
  get: (workflowId: string) => `/api/v1/workflows/${workflowId}`,

  /**
   * Create a new workflow
   */
  create: () => '/api/v1/workflows',

  /**
   * Update workflow
   */
  update: (workflowId: string) => `/api/v1/workflows/${workflowId}`,

  /**
   * Delete workflow
   */
  delete: (workflowId: string) => `/api/v1/workflows/${workflowId}`,

  /**
   * Update workflow graph (atomic replacement of all nodes and edges)
   */
  updateGraph: (workflowId: string) => `/api/v1/workflows/${workflowId}/graph`,

  /**
   * Add node to workflow
   */
  addNode: (workflowId: string) => `/api/v1/workflows/${workflowId}/nodes`,

  /**
   * Update node
   */
  updateNode: (workflowId: string, nodeId: string) =>
    `/api/v1/workflows/${workflowId}/nodes/${nodeId}`,

  /**
   * Delete node
   */
  deleteNode: (workflowId: string, nodeId: string) =>
    `/api/v1/workflows/${workflowId}/nodes/${nodeId}`,

  /**
   * Add edge to workflow
   */
  addEdge: (workflowId: string) => `/api/v1/workflows/${workflowId}/edges`,

  /**
   * Delete edge
   */
  deleteEdge: (workflowId: string, edgeId: string) =>
    `/api/v1/workflows/${workflowId}/edges/${edgeId}`,

  /**
   * Trigger workflow run
   */
  trigger: (workflowId: string) => `/api/v1/workflows/${workflowId}/runs`,
} as const

/**
 * Scan run endpoints: one execution of a scan (scans:read)
 */
export const workflowRunEndpoints = {
  /**
   * List workflow runs with optional filters
   */
  list: (filters?: WorkflowRunListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `/api/v1/workflow-runs${queryString}`
  },

  /**
   * Get workflow run by ID
   */
  get: (runId: string) => `/api/v1/workflow-runs/${runId}`,

  /**
   * Cancel a running workflow
   */
  cancel: (runId: string) => `/api/v1/workflow-runs/${runId}/cancel`,
} as const

// ============================================
// SCAN ENDPOINTS
// ============================================

import type { ScanConfigListFilters } from './scan-types'

/**
 * Scan endpoints for managing scans
 * Scans bind asset groups with scanners/workflows and schedules.
 */
export const scanEndpoints = {
  /**
   * List scans with optional filters
   */
  list: (filters?: ScanConfigListFilters) => {
    const queryString = filters ? buildQueryString(filters as Record<string, unknown>) : ''
    return `${API_BASE.SCANS}${queryString}`
  },

  /**
   * Get scan by ID
   */
  get: (scanId: string) => `${API_BASE.SCANS}/${scanId}`,

  /**
   * Get scan stats
   */
  stats: () => `${API_BASE.SCANS}/stats`,

  /**
   * Create a new scan
   */
  create: () => API_BASE.SCANS,

  /**
   * Update scan
   */
  update: (scanId: string) => `${API_BASE.SCANS}/${scanId}`,

  /**
   * Delete scan
   */
  delete: (scanId: string) => `${API_BASE.SCANS}/${scanId}`,

  /**
   * Activate scan
   */
  activate: (scanId: string) => `${API_BASE.SCANS}/${scanId}/activate`,

  /**
   * Pause scan
   */
  pause: (scanId: string) => `${API_BASE.SCANS}/${scanId}/pause`,

  /**
   * Disable scan
   */
  disable: (scanId: string) => `${API_BASE.SCANS}/${scanId}/disable`,

  /**
   * Trigger scan execution
   */
  trigger: (scanId: string) => `${API_BASE.SCANS}/${scanId}/trigger`,

  /**
   * Clone scan
   */
  clone: (scanId: string) => `${API_BASE.SCANS}/${scanId}/clone`,

  /**
   * Save an unsaved quick scan as a configuration ("Save as scan")
   */
  save: (scanId: string) => `${API_BASE.SCANS}/${scanId}/save`,

  /**
   * Next occurrences of a schedule, validated as saving would (stateless)
   */
  schedulePreview: () => `${API_BASE.SCANS}/schedule-preview`,

  /**
   * What a workflow scan would do before it is saved or started
   */
  workflowPreview: () => `${API_BASE.SCANS}/workflow-preview`,

  // ============================================
  // BULK OPERATIONS
  // ============================================

  /**
   * Bulk activate scans
   */
  bulkActivate: () => `${API_BASE.SCANS}/bulk/activate`,

  /**
   * Bulk pause scans
   */
  bulkPause: () => `${API_BASE.SCANS}/bulk/pause`,

  /**
   * Bulk disable scans
   */
  bulkDisable: () => `${API_BASE.SCANS}/bulk/disable`,

  /**
   * Bulk delete scans
   */
  bulkDelete: () => `${API_BASE.SCANS}/bulk/delete`,

  /**
   * List runs for a scan
   */
  listRuns: (scanId: string, page?: number, perPage?: number) => {
    let url = `${API_BASE.SCANS}/${scanId}/runs`
    const params: string[] = []
    if (page) params.push(`page=${page}`)
    if (perPage) params.push(`per_page=${perPage}`)
    if (params.length > 0) url += `?${params.join('&')}`
    return url
  },

  /**
   * Get latest run for a scan
   */
  latestRun: (scanId: string) => `${API_BASE.SCANS}/${scanId}/runs/latest`,

  /**
   * Get specific run for a scan
   */
  getRun: (scanId: string, runId: string) => `${API_BASE.SCANS}/${scanId}/runs/${runId}`,
} as const

// ============================================
// EXPOSURE EVENT ENDPOINTS
// ============================================

import type { ExposureListFilters } from './exposure-types'

/**
 * Exposure Event endpoints for attack surface monitoring.
 * Exposures track non-CVE attack surface changes (port opens, misconfigs, etc.)
 */
export const exposureEndpoints = {
  /**
   * List exposures with optional filters
   */
  list: (filters?: ExposureListFilters) => {
    if (!filters) return API_BASE.EXPOSURES
    // The API reads SINGULAR, repeated query params (url.Values: event_type,
    // severity, state, source) — not the comma-joined plural keys that the
    // generic buildQueryString produced, so filters were silently ignored and
    // "Needs Attention" still showed resolved/accepted exposures.
    const sp = new URLSearchParams()
    filters.event_types?.forEach((v) => sp.append('event_type', v))
    filters.severities?.forEach((v) => sp.append('severity', v))
    filters.states?.forEach((v) => sp.append('state', v))
    filters.sources?.forEach((v) => sp.append('source', v))
    // The API filters by a single `asset_id`.
    const assetId = filters.canonical_asset_id || filters.native_asset_id
    if (assetId) sp.set('asset_id', assetId)
    if (filters.search) sp.set('search', filters.search)
    if (filters.first_seen_after != null)
      sp.set('first_seen_after', String(filters.first_seen_after))
    if (filters.first_seen_before != null)
      sp.set('first_seen_before', String(filters.first_seen_before))
    if (filters.last_seen_after != null) sp.set('last_seen_after', String(filters.last_seen_after))
    if (filters.last_seen_before != null)
      sp.set('last_seen_before', String(filters.last_seen_before))
    if (filters.page != null) sp.set('page', String(filters.page))
    if (filters.per_page != null) sp.set('per_page', String(filters.per_page))
    if (filters.sort_by) sp.set('sort_by', filters.sort_by)
    if (filters.sort_order) sp.set('sort_order', filters.sort_order)
    const qs = sp.toString()
    return qs ? `${API_BASE.EXPOSURES}?${qs}` : API_BASE.EXPOSURES
  },

  /**
   * Get exposure by ID
   */
  get: (exposureId: string) => `${API_BASE.EXPOSURES}/${exposureId}`,

  /**
   * Get exposure statistics
   */
  stats: () => `${API_BASE.EXPOSURES}/stats`,

  /**
   * Create a new exposure event
   */
  create: () => API_BASE.EXPOSURES,

  /**
   * Delete exposure
   */
  delete: (exposureId: string) => `${API_BASE.EXPOSURES}/${exposureId}`,

  /**
   * Bulk ingest exposures
   */
  bulkIngest: () => `${API_BASE.EXPOSURES}/ingest`,

  /**
   * Resolve an exposure (mark as fixed)
   */
  resolve: (exposureId: string) => `${API_BASE.EXPOSURES}/${exposureId}/resolve`,

  /**
   * Accept an exposure (acknowledge risk)
   */
  accept: (exposureId: string) => `${API_BASE.EXPOSURES}/${exposureId}/accept`,

  /**
   * Mark exposure as false positive
   */
  markFalsePositive: (exposureId: string) => `${API_BASE.EXPOSURES}/${exposureId}/false-positive`,

  /**
   * Reactivate a resolved/accepted exposure
   */
  reactivate: (exposureId: string) => `${API_BASE.EXPOSURES}/${exposureId}/reactivate`,

  /**
   * Get exposure state change history
   */
  history: (exposureId: string) => `${API_BASE.EXPOSURES}/${exposureId}/history`,
} as const

// ============================================
// THREAT INTELLIGENCE ENDPOINTS
// ============================================

import type { ThreatIntelSource } from './threatintel-types'

/**
 * Threat Intelligence endpoints for EPSS and KEV data
 */
export const threatIntelEndpoints = {
  // ============================================
  // UNIFIED STATS
  // ============================================

  /**
   * Get unified threat intel stats (EPSS + KEV + sync status in one call)
   */
  stats: () => `${API_BASE.THREAT_INTEL}/stats`,

  // ============================================
  // SYNC STATUS
  // ============================================

  /**
   * Get sync status for all sources
   */
  syncStatuses: () => `${API_BASE.THREAT_INTEL}/sync`,

  /**
   * Get sync status for a specific source
   */
  syncStatus: (source: ThreatIntelSource) => `${API_BASE.THREAT_INTEL}/sync/${source}`,

  /**
   * Trigger sync. The API is POST /sync with the source in the body
   * (empty/"all" = all sources); there is no per-source /trigger path.
   */
  triggerSync: () => `${API_BASE.THREAT_INTEL}/sync`,

  /**
   * Enable/disable sync for a source: PATCH /sync/{source} with { enabled }.
   */
  setSyncEnabled: (source: ThreatIntelSource) => `${API_BASE.THREAT_INTEL}/sync/${source}`,

  // ============================================
  // CVE ENRICHMENT
  // ============================================

  /**
   * Enrich a single CVE with threat intel
   */
  enrichCVE: (cveId: string) => `${API_BASE.THREAT_INTEL}/enrich/${cveId}`,

  // ============================================
  // EPSS
  // ============================================

  /**
   * Get EPSS score for a CVE
   */
  epssScore: (cveId: string) => `${API_BASE.THREAT_INTEL}/epss/${cveId}`,

  /**
   * Get EPSS statistics
   */
  epssStats: () => `${API_BASE.THREAT_INTEL}/epss/stats`,

  // ============================================
  // KEV
  // ============================================

  /**
   * Get KEV entry for a CVE
   */
  kevEntry: (cveId: string) => `${API_BASE.THREAT_INTEL}/kev/${cveId}`,

  /**
   * Get KEV statistics
   */
  kevStats: () => `${API_BASE.THREAT_INTEL}/kev/stats`,
} as const

// ============================================
// PLATFORM SENSOR ENDPOINTS
// ============================================

/**
 * Platform scanning. The API serves only the organization's view of the
 * service (regions, state, tools, its own jobs); no tenant route lists,
 * reads or manages a platform sensor.
 */
export const platformEndpoints = {
  /** Platform scanning as the organization may use it. */
  scanning: () => `${API_BASE.PLATFORM}/scanning`,
} as const

// ============================================
// NOTIFICATION ENDPOINTS
// ============================================

/**
 * User notification endpoints (in-app notifications)
 */
export const notificationEndpoints = {
  /**
   * List notifications for current user
   */
  list: () => '/api/v1/notifications',

  /**
   * Get unread notification count
   */
  unreadCount: () => '/api/v1/notifications/unread-count',

  /**
   * Mark a single notification as read
   */
  markAsRead: (id: string) => `/api/v1/notifications/${id}/read`,

  /**
   * Mark all notifications as read
   */
  markAllAsRead: () => '/api/v1/notifications/read-all',

  /**
   * Get/update notification preferences
   */
  preferences: () => '/api/v1/notifications/preferences',
} as const

// ============================================
// ENDPOINT COLLECTIONS
// ============================================

/**
 * All API endpoints grouped by resource
 */
export const endpoints = {
  auth: authEndpoints,
  users: userEndpoints,
  tenants: tenantEndpoints,
  invitations: invitationEndpoints,
  assets: assetEndpoints,
  components: componentEndpoints,
  vulnerabilities: vulnerabilityEndpoints,
  findings: findingEndpoints,
  dashboard: dashboardEndpoints,
  auditLogs: auditLogEndpoints,
  sensors: sensorEndpoints,
  scanZones: scanZoneEndpoints,
  scanProfiles: scanProfileEndpoints,
  scannerTemplates: scannerTemplateEndpoints,
  tools: toolEndpoints,
  scanWorkflows: scanWorkflowEndpoints,
  scanRuns: scanRunEndpoints,
  scanManagement: scanManagementEndpoints,
  scans: scanEndpoints,
  exposures: exposureEndpoints,
  threatIntel: threatIntelEndpoints,
  workflows: workflowEndpoints,
  workflowRuns: workflowRunEndpoints,
  platform: platformEndpoints,
  notifications: notificationEndpoints,
  reports: reportsEndpoints,
} as const

/**
 * Export individual collections for convenience
 */
export {
  authEndpoints as auth,
  userEndpoints as users,
  tenantEndpoints as tenants,
  invitationEndpoints as invitations,
  assetEndpoints as assets,
  componentEndpoints as components,
  vulnerabilityEndpoints as vulnerabilities,
  findingEndpoints as findings,
  dashboardEndpoints as dashboard,
  auditLogEndpoints as auditLogs,
  sensorEndpoints as sensors,
  scanProfileEndpoints as scanProfiles,
  scannerTemplateEndpoints as scannerTemplates,
  toolEndpoints as tools,
  scanWorkflowEndpoints as scanWorkflows,
  scanRunEndpoints as scanRuns,
  scanManagementEndpoints as scanManagement,
  scanEndpoints as scans,
  exposureEndpoints as exposures,
  threatIntelEndpoints as threatIntel,
  workflowEndpoints as workflows,
  workflowRunEndpoints as workflowRuns,
  platformEndpoints as platform,
  notificationEndpoints as notifications,
  reportsEndpoints as reports,
}
