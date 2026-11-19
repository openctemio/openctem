/**
 * The page after a sign-in, from the landing (sign-in-landing.ts). Pure, so
 * the routing rules are unit-tested; `next` is always validated as a
 * same-origin path before it is used (no open redirect).
 */

import { twoFactorSetupHref } from '@/lib/auth/refresh-failure'
import { ACCOUNT_ONLY_PAGES, ACCOUNT_HOME_PATH } from '@/lib/middleware/config'
import { validateRedirectUrl } from '@/lib/redirect'

import type { Landing } from './sign-in-landing'

/** The route that decides the landing for the session in the cookies. */
export const CONTINUE_PATH = '/auth/continue'

/** On /account/organizations: the landing could not start an account session (no loop). */
export const CONTINUE_FAILED_PARAM = 'start_failed'

export function continueHref(next: string): string {
  const safe = validateRedirectUrl(next, '/')
  return safe === '/' ? CONTINUE_PATH : `${CONTINUE_PATH}?next=${encodeURIComponent(safe)}`
}

/**
 * Pages an account-only session may land on: the account pages and the
 * invitation page. Plain string work on the (already validated, same-origin)
 * path, no pattern that could run long on a crafted value.
 */
function accountSessionMayOpen(path: string): boolean {
  const cut = Math.min(...['?', '#'].map((c) => path.indexOf(c)).filter((i) => i >= 0), path.length)
  let bare = path.slice(0, cut)
  while (bare.length > 1 && bare.endsWith('/')) bare = bare.slice(0, -1)
  return (ACCOUNT_ONLY_PAGES as readonly string[]).includes(bare) || bare === '/invitations'
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
      return next !== '/' && accountSessionMayOpen(next) ? next : ACCOUNT_HOME_PATH
    case 'unavailable':
      return `${ACCOUNT_HOME_PATH}?${CONTINUE_FAILED_PARAM}=1`
    case 'signed_out':
      return '/login'
  }
}
