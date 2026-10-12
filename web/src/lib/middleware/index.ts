/**
 * Helpers for the Next.js proxy (src/proxy.ts).
 */

export {
  PUBLIC_ROUTES,
  API_PREFIX,
  ADMIN_CONSOLE_ROOT,
  ADMIN_CONSOLE_LOGIN,
  LOGIN_PATH,
  NEXT_PARAM,
  type PublicRoute,
} from './config'

export {
  isPublicRoute,
  isApiRoute,
  isAdminConsoleRoute,
  requiresAuth,
  looksLikeJwt,
  hasSessionCookie,
  hasAdminConsoleCookie,
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
