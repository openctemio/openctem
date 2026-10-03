/**
 * Next.js 16 Proxy (formerly middleware.ts).
 *
 * It lives in src/ because the app does: Next.js only picks up proxy.ts next
 * to the `app` directory. Until RFC-040 the file sat at the web root, where
 * Next.js never loaded it (the built middleware manifest was empty), so
 * neither the server-side auth redirect nor locale detection below has ever
 * run in any deployment; the client-side route guard does the sign-in
 * redirect. Turning them on changes sign-in behaviour (redirect loops with a
 * stale refresh cookie, locale/dir from Accept-Language) and needs its own
 * change and testing, so this file keeps them off and does one job:
 *
 *   Content-Security-Policy with a fresh script nonce for every request
 *   (src/lib/middleware/csp.ts). Next.js reads the nonce from the request's
 *   policy and stamps it on its own scripts; `x-nonce` hands it to the root
 *   layout for the next-themes inline script.
 *
 * @see https://nextjs.org/docs/app/guides/content-security-policy
 */

import { NextRequest, NextResponse } from 'next/server'
import { cspForRequest, generateNonce } from '@/lib/middleware/csp'

export function proxy(req: NextRequest) {
  const nonce = generateNonce()
  const csp = cspForRequest(nonce)

  const headers = new Headers(req.headers)
  headers.set('x-nonce', nonce)
  headers.set('Content-Security-Policy', csp)

  const response = NextResponse.next({ request: { headers } })
  response.headers.set('Content-Security-Policy', csp)
  return response
}

export const config = {
  matcher: [
    {
      // Documents only: API routes (JSON, the /api/v1 BFF and its WebSocket
      // upgrade), static files, images and prefetches carry no inline script
      // and need no nonce.
      source:
        '/((?!api/|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
}
