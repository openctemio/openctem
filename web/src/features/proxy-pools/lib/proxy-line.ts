/**
 * Proxy lines for the paste list (api pkg/domain/proxypool list.go): one
 * scheme://[user:pass@]host:port[#label] per line. The builder encodes the
 * credentials so nobody percent-encodes by hand, and the check flags a line
 * whose credentials would cross the network in clear text.
 */

export const PROXY_SCHEMES = ['http', 'https', 'socks5', 'socks5h'] as const
export type ProxyScheme = (typeof PROXY_SCHEMES)[number]

export interface ProxyLineFields {
  scheme: ProxyScheme
  host: string
  port: string
  username: string
  password: string
  label: string
}

/** Why a built line was refused (an i18n key suffix), or null when it is fine. */
export type ProxyLineProblem = 'host' | 'port' | 'user' | 'label'

const HOST_RE = /^[A-Za-z0-9._-]+$/

/**
 * The line for the fields, or the problem. A user name and a password are
 * percent-encoded as a whole (so "@", ":", "#", "/", "%" and a space survive);
 * an IPv6 host gets its brackets; the label may not hold "@", ":" or "/"
 * (the API refuses them).
 */
export function buildProxyLine(
  f: ProxyLineFields
): { line: string } | { problem: ProxyLineProblem } {
  const host = f.host.trim()
  const v6 = host.includes(':')
  if (!host || (v6 ? !/^[0-9A-Fa-f:.]+$/.test(host) : !HOST_RE.test(host)))
    return { problem: 'host' }
  const port = Number(f.port)
  if (!/^\d+$/.test(f.port.trim()) || port < 1 || port > 65535) return { problem: 'port' }
  const label = f.label.trim()
  if (/[@:/#]/.test(label) || /[\u0000-\u001f\u007f]/.test(label)) return { problem: 'label' }
  const hasAuth = f.username !== '' || f.password !== ''
  if (hasAuth && f.username === '') return { problem: 'user' }
  const auth = hasAuth
    ? `${encodeURIComponent(f.username)}${f.password ? `:${encodeURIComponent(f.password)}` : ''}@`
    : ''
  const addr = v6 ? `[${host}]` : host
  return { line: `${f.scheme}://${auth}${addr}:${port}${label ? `#${label}` : ''}` }
}

/** True for an address or name that is not on the public internet. */
export function isPrivateProxyHost(rawHost: string): boolean {
  const host = rawHost
    .trim()
    .replace(/^\[|\]$/g, '')
    .toLowerCase()
    .replace(/\.$/, '')
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])]
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    )
  }
  if (host.includes(':')) {
    return host === '::1' || /^f[cd]/.test(host) || /^fe[89ab]/.test(host)
  }
  // A single-label name, or a suffix reserved for private networks.
  return (
    !host.includes('.') ||
    /\.(local|internal|lan|corp|home|intranet|localdomain|private)$/.test(host)
  )
}

/** A line whose credentials would travel in clear text to a public proxy. */
export interface ClearCredentialLine {
  line: number
  scheme: 'http' | 'socks5' | 'socks5h'
  host: string
}

/**
 * The lines of a paste list that hold credentials for an http or socks proxy
 * on a public address: the proxy login (HTTP Basic, SOCKS5 user and password)
 * is not encrypted, so it can be read on the way. https:// wraps it in TLS.
 * Stored credentials (shown masked) count: they are sent the same way.
 */
export function clearCredentialLines(text: string): ClearCredentialLine[] {
  const out: ClearCredentialLine[] = []
  text.split('\n').forEach((raw, i) => {
    const line = raw.trim()
    if (!line || line.startsWith('#')) return
    const m = line.match(
      /^(http|socks5h?):\/\/([^/#?\s]*)@(\[[^\]]+\]|[^@/#?\s:]+)(?::\d+)?(?:[#/].*)?$/i
    )
    if (!m) return
    const host = m[3]
    if (isPrivateProxyHost(host)) return
    out.push({ line: i + 1, scheme: m[1].toLowerCase() as ClearCredentialLine['scheme'], host })
  })
  return out
}
