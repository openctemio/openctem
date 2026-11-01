/**
 * Scan identification markers (api docs/architecture/scan-identification.md):
 * the User-Agent and request headers a sensor's tools send to targets. The
 * rules mirror the API (api pkg/domain/scanident), which checks again.
 */

import type { Tr } from './format'

export interface IdentHeader {
  name: string
  value: string
  /** Platform layer only: no organization or program replaces it. */
  enforced?: boolean
}

export interface PlatformIdentLayer {
  user_agent: string
  user_agent_enforced: boolean
  headers: IdentHeader[]
}

export type IdentSource = 'platform' | 'platform_enforced' | 'organization'

export interface IdentMarker {
  name: string
  value: string
  source: IdentSource
}

export interface EffectiveIdentity {
  userAgent: string
  userAgentSource?: IdentSource
  headers: IdentMarker[]
  /** Organization headers an enforced platform header replaces. */
  overridden: string[]
}

export const MAX_PLATFORM_HEADERS = 4
export const MAX_ORGANIZATION_HEADERS = 6
export const MAX_HEADER_NAME = 64
export const MAX_HEADER_VALUE = 200
export const MAX_USER_AGENT = 256

const TOKEN = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/
const PRINTABLE = /^[\x20-\x7e]*$/
const REFUSED = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'te',
  'trailer',
  'upgrade',
  'authorization',
  'cookie',
])

/** Why a header name is refused, or null. */
export function headerNameError(name: string, t?: Tr): string | null {
  const n = name.trim()
  if (n === '') return t ? t('sensors.scanIdent.err.nameRequired') : 'Enter a header name.'
  if (n.length > MAX_HEADER_NAME || !TOKEN.test(n))
    return t
      ? t('sensors.scanIdent.err.nameToken')
      : "Letters, digits and !#$%&'*+-.^_`|~ only, no spaces or colon, at most 64."
  const lower = n.toLowerCase()
  if (REFUSED.has(lower) || lower.startsWith('proxy-'))
    return t
      ? t('sensors.scanIdent.err.nameRefused')
      : 'Connection, proxy and credential headers cannot be set.'
  return null
}

/** Why a header value is refused, or null. */
export function headerValueError(value: string, t?: Tr): string | null {
  const v = value.trim()
  if (v.length > MAX_HEADER_VALUE || !PRINTABLE.test(v))
    return t
      ? t('sensors.scanIdent.err.value')
      : 'Printable ASCII only, no line breaks, at most 200 characters.'
  return null
}

/** Why a User-Agent is refused, or null. */
export function userAgentError(ua: string, t?: Tr): string | null {
  const v = ua.trim()
  if (v.length > MAX_USER_AGENT)
    return t ? t('sensors.httpPolicy.uaTooLong') : 'At most 256 characters.'
  if (!PRINTABLE.test(v))
    return t ? t('sensors.httpPolicy.uaNotAscii') : 'Use printable ASCII characters only.'
  return null
}

/** Per-row errors of a list (index -> message), duplicates included. */
export function headerListErrors(headers: IdentHeader[], t?: Tr): Record<number, string> {
  const out: Record<number, string> = {}
  const seen = new Map<string, number>()
  headers.forEach((h, i) => {
    const err = headerNameError(h.name, t) ?? headerValueError(h.value, t)
    if (err) {
      out[i] = err
      return
    }
    const key = h.name.trim().toLowerCase()
    if (seen.has(key)) {
      out[i] = t
        ? t('sensors.scanIdent.err.duplicate')
        : 'This header is already listed (names are not case-sensitive).'
    } else {
      seen.set(key, i)
    }
  })
  return out
}

/** The list trimmed, as the API stores it. */
export function normalizeHeaders(headers: IdentHeader[]): IdentHeader[] {
  return headers.map((h) => ({
    name: h.name.trim(),
    value: h.value.trim(),
    ...(h.enforced ? { enforced: true } : {}),
  }))
}

/**
 * The merge the platform makes for every job: the union of both layers; the
 * organization wins a clash unless the platform enforces the header.
 */
export function mergeIdentity(
  platform: PlatformIdentLayer | undefined,
  orgUserAgent: string,
  orgHeaders: IdentHeader[]
): EffectiveIdentity {
  const headers: IdentMarker[] = []
  const overridden: string[] = []
  const idx = new Map<string, number>()
  for (const h of platform?.headers ?? []) {
    idx.set(h.name.toLowerCase(), headers.length)
    headers.push({
      name: h.name,
      value: h.value,
      source: h.enforced ? 'platform_enforced' : 'platform',
    })
  }
  for (const raw of orgHeaders) {
    const h = { name: raw.name.trim(), value: raw.value.trim() }
    if (!h.name) continue
    const key = h.name.toLowerCase()
    const i = idx.get(key)
    if (i !== undefined) {
      if (headers[i].source === 'platform_enforced') overridden.push(h.name)
      else headers[i] = { ...h, source: 'organization' }
      continue
    }
    idx.set(key, headers.length)
    headers.push({ ...h, source: 'organization' })
  }
  const ua = orgUserAgent.trim()
  let userAgent = ''
  let userAgentSource: IdentSource | undefined
  if (platform?.user_agent && platform.user_agent_enforced) {
    userAgent = platform.user_agent
    userAgentSource = 'platform_enforced'
  } else if (ua) {
    userAgent = ua
    userAgentSource = 'organization'
  } else if (platform?.user_agent) {
    userAgent = platform.user_agent
    userAgentSource = 'platform'
  }
  return { userAgent, userAgentSource, headers, overridden }
}

/** The request lines a target receives, for the preview. */
export function previewLines(e: EffectiveIdentity, host = 'target.example'): string[] {
  const lines = ['GET / HTTP/1.1', `Host: ${host}`]
  lines.push(`User-Agent: ${e.userAgent || '<tool default>'}`)
  for (const h of e.headers) lines.push(`${h.name}: ${h.value}`)
  return lines
}
