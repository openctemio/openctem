/**
 * The page after a sign-in, from the landing (sign-in-landing.ts). Pure, so
 * the routing rules are unit-tested; `next` is always validated as a
 * same-origin path before it is used (no open redirect).
 */

import { twoFactorSetupHref, welcomeNoticeHref } from '@/lib/auth/refresh-failure'
import { ACCOUNT_ONLY_PAGES, CONTINUE_PATH, WELCOME_PATH } from '@/lib/middleware/config'
import { validateRedirectUrl } from '@/lib/redirect'

import type { Landing } from './sign-in-landing'

/** The route that decides the landing for the session in the cookies. */
export { CONTINUE_PATH }

/** On /welcome: the landing could not start an account session (no loop). */
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
      if (next !== '/' && accountSessionMayOpen(next)) return next
      // Refused by the one organization: the account space says why
      // (welcomeNoticeHref keeps only known codes and a slug).
      return landing.refusal
        ? welcomeNoticeHref(landing.refusal.code, landing.refusal.slug)
        : WELCOME_PATH
    case 'unavailable':
      return `${WELCOME_PATH}?${CONTINUE_FAILED_PARAM}=1`
    case 'signed_out':
      return '/login'
  }
}
