/**
 * SCIM token types — mirror the backend /api/v1/scim-tokens contract (RFC-009).
 */

export interface ScimToken {
  id: string
  name: string
  prefix: string
  /** expired: past expires_at; revoked: withdrawn by an owner. */
  status: 'active' | 'expired' | 'revoked'
  created_at: string
  last_used_at?: string
  /** The token stops authenticating at this time. */
  expires_at: string
}

/** Lifetimes the console offers; the API accepts 1 to 365 days. */
export const SCIM_TOKEN_LIFETIME_DAYS = [30, 90, 180, 365] as const
export const SCIM_TOKEN_DEFAULT_LIFETIME_DAYS = 90

export interface CreateScimTokenRequest {
  name: string
  /** Required, 1 to 365. */
  expires_in_days: number
}

/** Create returns the plaintext token exactly once. */
export interface CreateScimTokenResponse {
  id: string
  name: string
  prefix: string
  token: string
  created_at: string
  expires_at: string
  endpoint: string
}

/** Rotate returns the replacement's plaintext once, and when the old token stops working. */
export interface RotateScimTokenResponse extends CreateScimTokenResponse {
  replaced_id: string
  replaced_expires_at: string
}

export interface ScimTokenListResponse {
  tokens: ScimToken[]
}
