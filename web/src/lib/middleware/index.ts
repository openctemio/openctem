/**
 * Helpers for the Next.js proxy (src/proxy.ts).
 */

export { PUBLIC_ROUTES, API_PREFIX, LOGIN_PATH, NEXT_PARAM, type PublicRoute } from './config'

export {
  isPublicRoute,
  isApiRoute,
  requiresAuth,
  looksLikeJwt,
  hasSessionCookie,
  isAuthenticated,
  returnPath,
  decideAuth,
  handleAuth,
  type AuthDecision,
  type AuthRequest,
  type CookieReader,
} from './auth'

export { LOCALE_COOKIE, detectLocale, negotiateLocale, localeFromAcceptLanguage } from './i18n'

export { buildCsp, cspForRequest, generateNonce } from './csp'
