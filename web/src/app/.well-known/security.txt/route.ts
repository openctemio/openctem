import { securityTxt } from '@/lib/legal'
import { legalSettings } from '@/lib/legal-settings'

export const dynamic = 'force-dynamic'

/**
 * /.well-known/security.txt (RFC 9116): how to report a vulnerability, from
 * the security contact set in the admin console (System > Legal). 404 when it
 * is turned off there.
 */
export async function GET() {
  const body = securityTxt(await legalSettings())
  if (!body) {
    return new Response('Not found\n', {
      status: 404,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    })
  }
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  })
}
