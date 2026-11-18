/**
 * The page after a sign-in, from the landing (sign-in-landing.ts). Pure, so
 * the routing rules are unit-tested; `next` is always validated as a
 * same-origin path before it is used (no open redirect).
 */

import { twoFactorSetupHref } from '@/lib/auth/refresh-failure'
import { isAccountOnlyPage } from '@/lib/middleware/auth'
import { WELCOME_PATH } from '@/lib/middleware/config'
import { validateRedirectUrl } from '@/lib/redirect'

import type { Landing } from './sign-in-landing'

/** The route that decides the landing for the session in the cookies. */
export const CONTINUE_PATH = '/auth/continue'

/** On /welcome: the landing could not start an account session (no loop). */
export const CONTINUE_FAILED_PARAM = 'start_failed'

export function continueHref(next: string): string {
  const safe = validateRedirectUrl(next, '/')
  return safe === '/' ? CONTINUE_PATH : `${CONTINUE_PATH}?next=${encodeURIComponent(safe)}`
}

/** Pages an account-only session may land on besides the account pages. */
function accountSessionMayOpen(path: string): boolean {
  const bare = path.split(/[?#]/)[0]
  return isAccountOnlyPage(bare) || bare === '/invitations' || bare.startsWith('/invitations/')
}

export function landingHref(landing: Landing, rawNext: string | null | undefined): string {
  const next = validateRedirectUrl(rawNext, '/')
  switch (landing.kind) {
    case 'organization':
      return next
    case 'choose':
      return '/select-tenant'
    case 'two_factor':
      return twoFactorSetupHref(next, landing.tenantId)
    case 'account':
      return next !== '/' && accountSessionMayOpen(next) ? next : WELCOME_PATH
    case 'unavailable':
      return `${WELCOME_PATH}?${CONTINUE_FAILED_PARAM}=1`
    case 'signed_out':
      return '/login'
  }
}
