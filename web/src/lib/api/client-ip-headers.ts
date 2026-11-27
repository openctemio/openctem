/**
 * Which client address the web server passes on to the API.
 *
 * The API uses the caller's address for an organization's IP allowlist, the
 * audit log, session details and its per-address request limits. When the
 * browser talks to the API through this server, the API sees this server's
 * address unless this server forwards the original one.
 *
 * `X-Real-IP` / `X-Forwarded-For` on an incoming request are only trustworthy
 * when a reverse proxy in front of this server sets them. Without one, they are
 * whatever the caller wrote. So an address is forwarded only when the operator
 * says such a proxy exists:
 *
 *   TRUST_PROXY_HEADERS=true
 *
 * Default (unset / anything else): nothing is forwarded, and the API counts
 * the request against this server's own address.
 *
 * Even when trusted, the raw headers are never passed through. The address is
 * the right-most `X-Forwarded-For` entry, the one the proxy in front of this
 * server wrote for the connection it received; entries to its left came from
 * further away and are not believed. Only when `X-Forwarded-For` is absent is
 * `X-Real-IP` used. A malformed value forwards nothing. The API receives
 * exactly one address, in both headers.
 */

export const CLIENT_IP_HEADERS = ['x-real-ip', 'x-forwarded-for'] as const

/** The part of a request's headers this module reads. */
type HeaderSource = Pick<Headers, 'get'>

/** True when the operator has declared a header-setting reverse proxy. */
export function trustProxyHeaders(envValue: string | undefined = process.env.TRUST_PROXY_HEADERS) {
  return envValue === 'true'
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

/** Returns the address in canonical form, or null when it is not a bare IP. */
export function parseIpAddress(raw: string | null | undefined): string | null {
  const value = (raw ?? '').trim()
  if (!value || value.length > 45) return null
  if (IPV4.test(value)) return value
  if (!value.includes(':') || !/^[0-9a-fA-F:.]+$/.test(value)) return null
  try {
    // The URL parser validates and normalises an IPv6 literal.
    const host = new URL(`http://[${value}]/`).hostname
    return host.slice(1, -1)
  } catch {
    return null
  }
}

/**
 * The client address the trusted proxy in front of this server reported, or
 * null. Callers must check {@link trustProxyHeaders} first.
 */
export function proxiedClientAddress(incoming: HeaderSource): string | null {
  const xff = incoming.get('x-forwarded-for')
  if (xff !== null && xff.trim() !== '') {
    // Several header lines arrive joined with ", ": one list, in order.
    const entries = xff.split(',')
    return parseIpAddress(entries[entries.length - 1])
  }
  return parseIpAddress(incoming.get('x-real-ip'))
}

/**
 * Returns the client-IP headers to send to the backend, derived from the
 * incoming request. Empty unless `trusted` is true and an address is found.
 */
export function clientIpHeaders(
  incoming: HeaderSource,
  trusted: boolean = trustProxyHeaders()
): Array<[string, string]> {
  if (!trusted) return []
  const address = proxiedClientAddress(incoming)
  if (!address) return []
  return CLIENT_IP_HEADERS.map((name) => [name, address])
}

/** Copies {@link clientIpHeaders} onto the outgoing backend request headers. */
export function applyClientIpHeaders(
  outgoing: Headers,
  incoming: HeaderSource,
  trusted: boolean = trustProxyHeaders()
): void {
  for (const name of CLIENT_IP_HEADERS) outgoing.delete(name)
  for (const [name, value] of clientIpHeaders(incoming, trusted)) {
    outgoing.set(name, value)
  }
}
