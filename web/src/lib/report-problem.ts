import { REPORT_ISSUE_URL, BUG_TEMPLATE } from '@/config/help-links'

/**
 * "Report this problem": the safe diagnostics a report may carry. They are
 * shown to the person before anything is sent (the issue form opens in their
 * browser; the platform itself makes no outbound call), and they can be
 * copied instead for an install without internet access.
 *
 * Never in here: organization or user names, e-mail addresses, domains or
 * host names, ids, query strings, finding or asset data, error messages
 * (they can quote data). The route is reduced to its shape.
 */
export interface Diagnostics {
  version: string
  channel: string
  /** "app" (the tenant console) or "admin" (the platform console). */
  console: 'app' | 'admin'
  browser: string
  /** Route with ids and parameters stripped, e.g. /findings/:id. */
  route: string
  /** Request ID of the failed API call, when there is one. */
  requestId: string
  /** Error code or kind (e.g. RATE_LIMITED, chunk_load), never the message. */
  errorCode: string
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const HEX_TOKEN = /^[0-9a-f]{8,}$/i

/**
 * Keeps the static words of a path and replaces every segment that could be
 * an identifier by ":id": anything with a digit (uuid, number, CVE id, token),
 * long hex strings and very long segments. Query and fragment are dropped.
 */
export function stripRoute(path: string): string {
  const clean = path.split(/[?#]/)[0] ?? ''
  const segs = clean.split('/').filter(Boolean)
  if (segs.length === 0) return '/'
  return (
    '/' +
    segs
      .map((s) => {
        let seg = s
        try {
          seg = decodeURIComponent(s)
        } catch {
          return ':id'
        }
        if (UUID.test(seg) || HEX_TOKEN.test(seg) || /\d/.test(seg) || seg.length > 32) return ':id'
        if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(seg)) return ':id'
        return seg
      })
      .join('/')
  )
}

/** "Chrome 131", "Firefox 133", "Safari 18", "Edge 131" or "unknown": no full user-agent string. */
export function browserName(ua: string): string {
  const rules: [string, RegExp][] = [
    ['Edge', /Edg\/(\d+)/],
    ['Firefox', /Firefox\/(\d+)/],
    ['Chrome', /(?:Chrome|CriOS)\/(\d+)/],
    ['Safari', /Version\/(\d+)[\d.]*.*Safari/],
  ]
  for (const [name, re] of rules) {
    const m = re.exec(ua)
    if (m) return `${name} ${m[1]}`
  }
  return 'unknown'
}

/** An error code safe to share: short, uppercase/lowercase word characters only. */
export function safeErrorCode(code: unknown): string {
  return typeof code === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(code) ? code : ''
}

/** A request ID is a uuid or short token; anything else is dropped. */
export function safeRequestId(id: unknown): string {
  return typeof id === 'string' && /^[A-Za-z0-9_-]{6,64}$/.test(id) ? id : ''
}

/** The text "Copy diagnostics" puts on the clipboard (also pasted into the issue). */
export function diagnosticsText(d: Diagnostics): string {
  const lines = [
    `Version: ${d.version}`,
    `Channel: ${d.channel}`,
    `Console: ${d.console}`,
    `Browser: ${d.browser}`,
    `Route: ${d.route}`,
  ]
  if (d.requestId) lines.push(`Request ID: ${d.requestId}`)
  if (d.errorCode) lines.push(`Error code: ${d.errorCode}`)
  return lines.join('\n')
}

/**
 * The project's bug form with the diagnostics filled in. The parameter names
 * are the field ids of .github/ISSUE_TEMPLATE/bug.yml. Only ever built on the
 * project's own issue URL: an operator's tracker gets no parameters.
 */
export function bugReportUrl(d: Diagnostics): string {
  const q = new URLSearchParams({ template: BUG_TEMPLATE })
  q.set('version', d.version)
  q.set('browser', d.browser)
  q.set('route', d.route)
  q.set('diagnostics', diagnosticsText(d))
  return `${REPORT_ISSUE_URL}?${q.toString()}`
}
