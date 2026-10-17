/**
 * Next.js 16 Proxy (formerly middleware.ts).
 *
 * It lives in src/ because the app does: Next.js only picks up proxy.ts next
 * to the `app` directory. For every page request it does three things:
 *
 * 1. Route protection (src/lib/middleware/auth.ts). A page that needs a session
 *    and has no session cookie of the right shape is redirected to
 *    /login?next=<page>; the admin console (RFC-022) to /admin/login?next=<page>.
 *    Cookie presence and shape only, no network call: the API validates the
 *    session on every call, and a stale cookie is cleared by the client on its
 *    first 401 (src/lib/auth/session-expired.ts). Public pages: PUBLIC_ROUTES.
 *
 * 2. Locale (src/lib/middleware/i18n.ts): the `locale` cookie, then
 *    Accept-Language, among the locales the app ships; passed to the root
 *    layout as `x-locale`.
 *
 * 3. Content-Security-Policy with a fresh script nonce
 *    (src/lib/middleware/csp.ts). Next.js reads the nonce from the request's
 *    policy and stamps it on its own scripts; `x-nonce` hands it to the root
 *    layout for the next-themes inline script.
 *
 * 4. Invitation links from before RFC-041 (/invitations/{token}) get a 307 to
 *    /invitations#token=..., so the token leaves the path
 *    (src/lib/middleware/invitation-link.ts).
 *
 * 0. The admin plane (src/lib/middleware/admin-plane.ts): with the console on
 *    its own origin, a console-site request reaches only the console and a
 *    main-site request never does (404). It also runs for API routes, which
 *    then return at once.
 *
 * 5. CSRF (src/lib/server-auth-cookies.ts). A state-changing request to a page
 *    is a Server Action (sign-in, registration, password reset, invitation,
 *    second factor, SSO start, ...): it must come from this origin and echo
 *    the `csrf_token` cookie in `X-CSRF-Token`, or it gets a 403 before any
 *    action runs. Every page response that lacks the cookie sets one, so the
 *    pre-session forms have a token to echo. API routes check themselves.
 *
 * Keep it cheap: no database, no API call, no JWT verification.
 *
 * @see https://nextjs.org/docs/app/guides/content-security-policy
 */

import { NextRequest, NextResponse } from 'next/server'
import { handleAuth } from '@/lib/middleware/auth'
import { detectLocale } from '@/lib/middleware/i18n'
import { cspForRequest, generateNonce } from '@/lib/middleware/csp'
import { handleLegacyInvitationLink } from '@/lib/middleware/invitation-link'
import { csrfRejection, ensureCsrfCookie } from '@/lib/server-auth-cookies'
import { ADMIN_PLANE_HEADER, decidePlane } from '@/lib/middleware/admin-plane'

export function proxy(req: NextRequest) {
  // The platform console on its own origin: each site serves only its own
  // plane (src/lib/middleware/admin-plane.ts). First, for pages and API routes.
  const plane = decidePlane(req.nextUrl.pathname, req.headers.get(ADMIN_PLANE_HEADER))
  if (plane === 'not-found') return new NextResponse('Not Found', { status: 404 })
  if (plane === 'to-console') {
    const url = req.nextUrl.clone()
    url.pathname = '/admin'
    url.search = ''
    return NextResponse.redirect(url)
  }
  // API routes come here only for the plane gate; they check the rest
  // themselves (CSRF, auth) and need no page headers.
  if (req.nextUrl.pathname.startsWith('/api/')) return NextResponse.next()

  // Server Actions: same origin and the double-submit pair, before anything runs.
  const csrf = csrfRejection(req)
  if (csrf) return csrf

  // Invitation links from before RFC-041 carry the token in the path.
  const invitation = handleLegacyInvitationLink(req)
  if (invitation) return invitation

  const redirect = handleAuth(req)
  if (redirect) {
    ensureCsrfCookie(req, redirect)
    return redirect
  }

  const nonce = generateNonce()
  const csp = cspForRequest(nonce)

  const headers = new Headers(req.headers)
  headers.set('x-nonce', nonce)
  headers.set('x-locale', detectLocale(req))
  headers.set('Content-Security-Policy', csp)

  const response = NextResponse.next({ request: { headers } })
  response.headers.set('Content-Security-Policy', csp)
  ensureCsrfCookie(req, response)
  return response
}

export const config = {
  matcher: [
    {
      // Documents only: API routes (JSON, the /api/v1 BFF and its WebSocket
      // upgrade, /api/health), the API's OAuth metadata and endpoints for MCP
      // clients (/.well-known/oauth-*, /oauth/authorize|token|revoke|register;
      // RFC-062),
      // Next.js assets, and static files carry no inline script, need no nonce
      // and handle their own auth. The consent page /oauth/consent is a page.
      source:
        '/((?!api/|\\.well-known/oauth-|oauth/(?:authorize|token|revoke|register)|_next/|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|txt|xml|json|webmanifest|js|css|map|woff2?)$).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
    // API routes, for the admin-plane gate only (proxy returns at once).
    { source: '/api/:path*' },
  ],
}
