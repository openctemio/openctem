/**
 * Account Types
 *
 * Type definitions for user account management
 */

// ============================================
// USER PROFILE
// ============================================

export interface UserProfile {
  id: string
  email: string
  name: string
  avatar_url?: string
  phone?: string
  created_at: string
  updated_at: string
  email_verified: boolean
  /** "local" = signs in with a password; anything else is an identity provider. */
  auth_provider: 'local' | 'google' | 'github' | 'microsoft' | 'oidc' | 'saml'
}

export interface UpdateProfileInput {
  name?: string
  phone?: string
}

export interface UpdateAvatarInput {
  avatar_data: string // Base64 encoded image
}

// ============================================
// SECURITY
// ============================================

export interface ChangePasswordInput {
  current_password: string
  new_password: string
  confirm_password: string
  /** Also revoke every API key the person owns (connected apps always go). */
  revoke_api_keys?: boolean
}

/** GET /api/v1/users/me/2fa */
export interface TwoFactorStatus {
  /** false for accounts that sign in through an identity provider (it owns 2FA) */
  supported: boolean
  enabled: boolean
  enabled_at?: string
  recovery_codes_remaining: number
  /** an organization the user belongs to requires 2FA */
  required_by_organization: boolean
  /**
   * The platform's two-factor floor covers the user but their grace period
   * has not ended: the date from which sign-in is gated. They can set up now.
   */
  grace_due_at?: string
}

/** POST /api/v1/users/me/2fa/setup — nothing changes until it is confirmed */
export interface TwoFactorSetupResponse {
  secret: string
  otpauth_uri: string
}

/** Recovery codes, returned once by enable and regenerate */
export interface RecoveryCodesResponse {
  recovery_codes: string[]
}

/** Confirm 2FA setup: the current password and the authenticator code. */
export interface TwoFactorEnableInput {
  password: string
  code: string
}

export interface TwoFactorDisableInput {
  password: string
  /** authenticator code or an unused recovery code */
  code: string
}

// ============================================
// SESSIONS
// ============================================

/** One active sign-in, as GET /api/v1/users/me/sessions returns it. */
export interface Session {
  id: string
  ip_address?: string
  user_agent?: string
  created_at: string
  last_activity_at: string
  is_current: boolean
}

export interface SessionListResponse {
  sessions: Session[]
  /** API keys the person owns, in every organization. */
  active_api_keys?: number
}

// ============================================
// PREFERENCES
// ============================================

export interface UserPreferences {
  theme: 'light' | 'dark' | 'system'
  language: string
  /** Server-stored; absent from an older API (read as default). */
  findings_informational?: FindingsInformationalPreference
  timezone: string
  date_format: string
  time_format: '12h' | '24h'
  /**
   * Browser-local (no server field): set on /account/notifications, under
   * "This browser". Optional because older stored objects may lack it.
   */
  desktop_notifications?: boolean
}

/** Whether the findings work views show informational findings: default = the organization's. */
export type FindingsInformationalPreference = 'default' | 'include' | 'exclude'

export interface UpdatePreferencesInput {
  theme?: 'light' | 'dark' | 'system'
  language?: string
  timezone?: string
  date_format?: string
  time_format?: '12h' | '24h'
  findings_informational?: FindingsInformationalPreference
}

// ============================================
// ACTIVITY
// ============================================

export interface ActivityLog {
  id: string
  event_type: ActivityEventType
  description: string
  ip_address: string
  user_agent: string
  location?: string
  created_at: string
  metadata?: Record<string, unknown>
}

export type ActivityEventType =
  | 'login'
  | 'logout'
  | 'password_change'
  | 'profile_update'
  | '2fa_enabled'
  | '2fa_disabled'
  | 'session_revoked'
  | 'api_key_created'
  | 'api_key_revoked'

export interface ActivityListResponse {
  data: ActivityLog[]
  total: number
  page: number
  per_page: number
}

// ============================================
// CONSTANTS
// ============================================

export const ACTIVITY_EVENT_LABELS: Record<ActivityEventType, string> = {
  login: 'Signed in',
  logout: 'Signed out',
  password_change: 'Password changed',
  profile_update: 'Profile updated',
  '2fa_enabled': 'Two-factor authentication enabled',
  '2fa_disabled': 'Two-factor authentication disabled',
  session_revoked: 'Session revoked',
  api_key_created: 'API key created',
  api_key_revoked: 'API key revoked',
}

export const SUPPORTED_LANGUAGES = [
  { value: 'en', label: 'English' },
  { value: 'vi', label: 'Tiếng Việt' },
  { value: 'ja', label: '日本語' },
  { value: 'ko', label: '한국어' },
  { value: 'zh', label: '中文' },
] as const
