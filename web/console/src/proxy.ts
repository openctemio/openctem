/**
 * Next.js proxy of the platform console (RFC-022 revision 21). For every page
 * request:
 *
 * 1. CSRF: a state-changing request to a page (a Server Action) must come from
 *    this origin and echo the `csrf_token` cookie, or it gets a 403; every page
 *    response that lacks the cookie sets one, for the sign-in steps to echo
 *    before a console session exists. The API proxy checks its own requests.
 * 2. Locale (shared with the tenant app).
 * 3. The console's strict Content-Security-Policy with a fresh nonce.
 *
 * No session redirect: the console's session cookie is scoped to its API and
 * its CSRF token lives in memory, so the console shell asks the API and sends
 * a browser without a session to /login. The API checks every call.
 */

import { NextRequest, NextResponse } from 'next/server'

import { detectLocale } from '@/lib/middleware/i18n'
import { generateNonce } from '@/lib/middleware/csp'
import { csrfRejection, ensureCsrfCookie } from '@/lib/server-auth-cookies'
import { buildConsoleCsp } from '@console/lib/csp'

export function proxy(req: NextRequest) {
  const csrf = csrfRejection(req)
  if (csrf) return csrf

  const nonce = generateNonce()
  const csp = buildConsoleCsp(nonce, process.env.NODE_ENV === 'development')

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
      // Documents only: API routes, Next.js assets and static files.
      source:
        '/((?!api/|_next/|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|txt|xml|json|webmanifest|js|css|map|woff2?)$).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
}
