/**
 * Helpers for the Next.js proxy (src/proxy.ts).
 */

export {
  PUBLIC_ROUTES,
  ACCOUNT_ONLY_PAGES,
  WELCOME_PATH,
  API_PREFIX,
  LOGIN_PATH,
  NEXT_PARAM,
  type PublicRoute,
} from './config'

export {
  isPublicRoute,
  isApiRoute,
  requiresAuth,
  looksLikeJwt,
  hasSessionCookie,
  isAccountOnlySession,
  isAccountOnlyPage,
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
