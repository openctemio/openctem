import { headers } from 'next/headers'

/**
 * The browser's User-Agent and address, forwarded on the server-to-server
 * calls a sign-in makes (password, SSO, social), so the session the API
 * creates shows the real device in My account → Sessions and in the audit
 * log, instead of this server. The API only believes X-Forwarded-For when
 * this server is in its SERVER_TRUSTED_PROXIES.
 */
export async function browserContextHeaders(): Promise<Record<string, string>> {
  try {
    const h = await headers()
    const out: Record<string, string> = {}
    const ua = h.get('user-agent')
    if (ua) out['User-Agent'] = ua
    const fwd = h.get('x-forwarded-for') || h.get('x-real-ip')
    if (fwd) out['X-Forwarded-For'] = fwd
    return out
  } catch {
    // Outside a request.
    return {}
  }
}
