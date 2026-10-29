/**
 * Security-header posture of an origin: the `http_posture` property a sensor
 * reports (header names and cookie flags only, never values). The property
 * can be absent (not inspected yet) or in a shape this build does not know,
 * so every read is defensive and an unknown shape reads as "no data".
 */

/** The headers the card lists, in display order. */
export const POSTURE_HEADERS = [
  'strict_transport_security',
  'content_security_policy',
  'x_frame_options',
  'x_content_type_options',
  'referrer_policy',
  'permissions_policy',
] as const
export type PostureHeader = (typeof POSTURE_HEADERS)[number]

/** English fallback label of a header, by its canonical key. */
export const POSTURE_HEADER_NAME: Record<PostureHeader, string> = {
  strict_transport_security: 'Strict-Transport-Security',
  content_security_policy: 'Content-Security-Policy',
  x_frame_options: 'X-Frame-Options',
  x_content_type_options: 'X-Content-Type-Options',
  referrer_policy: 'Referrer-Policy',
  permissions_policy: 'Permissions-Policy',
}

/** Short names a sensor may use for a header. */
const ALIASES: Record<string, PostureHeader> = {
  hsts: 'strict_transport_security',
  csp: 'content_security_policy',
  frame_options: 'x_frame_options',
  xfo: 'x_frame_options',
  content_type_options: 'x_content_type_options',
  nosniff: 'x_content_type_options',
}

export interface PostureCookie {
  name: string
  secure: boolean | null
  httpOnly: boolean | null
  sameSite: string
}

export interface OriginPosture {
  headers: { key: PostureHeader; present: boolean }[]
  cookies: PostureCookie[]
}

function canon(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_')
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function flag(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null
}

function present(v: unknown): boolean {
  if (typeof v === 'boolean') return v
  if (typeof v === 'string') return v.trim() !== ''
  if (typeof v === 'number') return v !== 0
  if (Array.isArray(v)) return v.length > 0
  return isRecord(v)
}

/** Reads the posture from an asset's properties; null when there is none. */
export function readPosture(properties: unknown): OriginPosture | null {
  if (!isRecord(properties)) return null
  // Read by listing the entries: the key is not in the typed registry yet.
  const raw = Object.entries(properties).find(([k]) => k === 'http_posture')?.[1]
  if (!isRecord(raw)) return null

  const found = new Set<PostureHeader>()
  const mark = (name: string, on: boolean) => {
    const c = canon(name)
    const key = (POSTURE_HEADERS as readonly string[]).includes(c)
      ? (c as PostureHeader)
      : ALIASES[c]
    if (key && on) found.add(key)
  }
  // Either a `headers` list of present names / map of name to value, or the
  // headers as top-level keys.
  const hdrs = raw.headers
  if (Array.isArray(hdrs)) {
    for (const h of hdrs) if (typeof h === 'string') mark(h, true)
  } else if (isRecord(hdrs)) {
    for (const [k, v] of Object.entries(hdrs)) mark(k, present(v))
  }
  for (const [k, v] of Object.entries(raw))
    if (k !== 'headers' && k !== 'cookies') mark(k, present(v))

  const cookies: PostureCookie[] = []
  if (Array.isArray(raw.cookies)) {
    for (const c of raw.cookies.slice(0, 100)) {
      if (!isRecord(c) || typeof c.name !== 'string') continue
      cookies.push({
        name: c.name,
        secure: flag(c.secure),
        httpOnly: flag(c.http_only ?? c.httponly),
        sameSite:
          typeof (c.same_site ?? c.samesite) === 'string' ? String(c.same_site ?? c.samesite) : '',
      })
    }
  }

  const known = found.size > 0 || cookies.length > 0 || Object.keys(raw).length > 0
  if (!known) return null
  return { headers: POSTURE_HEADERS.map((key) => ({ key, present: found.has(key) })), cookies }
}
