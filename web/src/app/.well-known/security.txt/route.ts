import { securityTxt } from '@/lib/legal'

export const dynamic = 'force-dynamic'

/**
 * /.well-known/security.txt (RFC 9116): how to report a vulnerability, from
 * SECURITY_CONTACT (and SECURITY_POLICY_URL). 404 when no contact is set.
 */
export function GET() {
  const body = securityTxt()
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
