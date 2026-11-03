/**
 * A request that needs an organization, sent with an account-only token.
 *
 * The API answers `401 TENANT_REQUIRED` for every route outside the account
 * allow-list (api RFC-141). It is not an expired session: the person is
 * signed in and has no organization open, so the page they asked for does not
 * exist for them. The shared API client sends them to /welcome, once.
 */

import { WELCOME_PATH } from '@/lib/middleware/config'

export const TENANT_REQUIRED_CODE = 'TENANT_REQUIRED'

export function isTenantRequired(
  err: { statusCode?: number; code?: string } | null | undefined
): boolean {
  return !!err && err.statusCode === 401 && err.code === TENANT_REQUIRED_CODE
}

let routing = false

/**
 * Goes to /welcome unless the person is already in the account space (those
 * pages call only allow-listed routes, so a refusal there is a bug to show,
 * not a loop to enter).
 */
export function routeToWelcomeOnce(location: Pick<Location, 'pathname' | 'assign'>): boolean {
  if (routing) return false
  const path = location.pathname
  if (path === WELCOME_PATH || path.startsWith(`${WELCOME_PATH}/`) || path.startsWith('/account')) {
    return false
  }
  routing = true
  location.assign(WELCOME_PATH)
  return true
}

/** Test hook: forget that a redirect already started. */
export function resetTenantRequiredRouting(): void {
  routing = false
}
