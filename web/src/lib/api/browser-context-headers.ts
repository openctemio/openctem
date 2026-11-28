import { headers } from 'next/headers'

import { clientIpHeaders, trustProxyHeaders } from '@/lib/api/client-ip-headers'
import { REFRESH_BINDING_HEADER, refreshBindingFromCookieHeader } from '@/lib/refresh-binding'

/**
 * The browser's User-Agent and address, forwarded on the server-to-server
 * calls a sign-in makes (password, SSO, social), so the session the API
 * creates shows the real device in My account → Sessions and in the audit
 * log, instead of this server.
 *
 * The address follows the same rule as the API proxy
 * (`@/lib/api/client-ip-headers`): it is sent only when TRUST_PROXY_HEADERS
 * is on, and then it is the one address the proxy in front of this server
 * reported, never the incoming header as written. With the setting off the
 * API sees this server's own address.
 *
 * The browser's refresh client binding (`@/lib/refresh-binding`) goes along
 * as `X-Refresh-Client-Binding`, so the API's rotation grace on `/auth/refresh`
 * and `/auth/token` knows the browser and not just its user agent.
 */
export async function browserContextHeaders(): Promise<Record<string, string>> {
  try {
    const h = await headers()
    const out: Record<string, string> = {}
    const ua = h.get('user-agent')
    if (ua) out['User-Agent'] = ua
    for (const [name, value] of clientIpHeaders(h, trustProxyHeaders())) out[name] = value
    const binding = refreshBindingFromCookieHeader(h.get('cookie'))
    if (binding) out[REFRESH_BINDING_HEADER] = binding
    return out
  } catch {
    // Outside a request.
    return {}
  }
}
