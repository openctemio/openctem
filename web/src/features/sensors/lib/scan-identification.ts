/**
 * Scan identification markers (api docs/architecture/scan-identification.md):
 * the User-Agent (one value or a rotation list), request headers and query
 * parameter a sensor's tools send to targets, and whether identification is
 * required. The rules mirror the API (api pkg/domain/scanident and contract
 * identity), which checks again.
 */

import type { Tr } from './format'

export interface IdentHeader {
  name: string
  value: string
  /** Platform layer only: no organization or program replaces it. */
  enforced?: boolean
}

export interface IdentQuery {
  name: string
  value: string
}

export interface PlatformIdentLayer {
  user_agent: string
  /** A rotation list instead of user_agent. */
  user_agents?: string[]
  /** Locks the User-Agent or the list. */
  user_agent_enforced: boolean
  headers: IdentHeader[]
  query?: IdentQuery | null
  query_enforced?: boolean
  identification_required?: boolean
}

/** The organization's layer as the merge reads it. */
export interface OrgIdentLayer {
  userAgent: string
  userAgents?: string[]
  headers: IdentHeader[]
  query?: IdentQuery | null
  required?: boolean
}

export type IdentSource = 'platform' | 'platform_enforced' | 'organization'

export interface IdentMarker {
  name: string
  value: string
  source: IdentSource
}

export interface EffectiveIdentity {
  /** The first value of userAgents (what a sensor without rotation sends). */
  userAgent: string
  /** The winning layer's whole list (one value for a single User-Agent). */
  userAgents: string[]
  userAgentSource?: IdentSource
  headers: IdentMarker[]
  /** Organization headers an enforced platform header replaces. */
  overridden: string[]
  query?: IdentQuery
  querySource?: IdentSource
  /** Logical OR of the layers; requiredBy names them. */
  required: boolean
  requiredBy: IdentSource[]
}

export const MAX_PLATFORM_HEADERS = 4
export const MAX_ORGANIZATION_HEADERS = 6
export const MAX_HEADER_NAME = 64
export const MAX_HEADER_VALUE = 200
export const MAX_USER_AGENT = 256
/** contract identity.MaxUserAgents */
export const MAX_USER_AGENTS = 200
export const MAX_QUERY_PART = 64

const QUERY_PART = /^[A-Za-z0-9._~-]{1,64}$/

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

/** The rotation list a text area holds: one value per line, trimmed, blank lines dropped. */
export function parseUserAgentList(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '')
}

export interface ListError {
  /** 1-based line of the text area; 0 for the list as a whole. */
  line: number
  message: string
}

/**
 * The errors of a rotation list text area, per line (printable ASCII, at
 * most 256 characters, no duplicate) and for the list (at most 200 values).
 * The same rules as contract identity.CheckUserAgents.
 */
export function userAgentListErrors(text: string, t?: Tr): ListError[] {
  const out: ListError[] = []
  const seen = new Set<string>()
  let count = 0
  text.split('\n').forEach((raw, i) => {
    const v = raw.trim()
    if (v === '') return
    count++
    const line = i + 1
    if (v.length > MAX_USER_AGENT) {
      out.push({ line, message: t ? t('sensors.scanIdent.err.uaLong') : 'At most 256 characters.' })
    } else if (!PRINTABLE.test(v)) {
      out.push({
        line,
        message: t ? t('sensors.scanIdent.err.uaAscii') : 'Printable ASCII only.',
      })
    } else if (seen.has(v)) {
      out.push({
        line,
        message: t ? t('sensors.scanIdent.err.uaDuplicate') : 'Already in the list.',
      })
    }
    seen.add(v)
  })
  if (count > MAX_USER_AGENTS)
    out.unshift({
      line: 0,
      message: t
        ? t('sensors.scanIdent.err.uaTooMany', '', { max: MAX_USER_AGENTS })
        : `At most ${MAX_USER_AGENTS} values.`,
    })
  return out
}

/** Why a layer's single User-Agent and list cannot both be set, or null. */
export function userAgentBothError(single: string, list: string[], t?: Tr): string | null {
  if (single.trim() !== '' && list.length > 0)
    return t
      ? t('sensors.scanIdent.err.uaBoth')
      : 'Use either one User-Agent or a rotation list: clear the User-Agent to rotate.'
  return null
}

/** The query parameter a form holds: null when both parts are empty. */
export function normalizeQuery(q: IdentQuery | null | undefined): IdentQuery | null {
  if (!q) return null
  const name = q.name.trim()
  const value = q.value.trim()
  return name === '' && value === '' ? null : { name, value }
}

/** Why a query parameter is refused, or null (an empty one is none). */
export function queryError(q: IdentQuery | null | undefined, t?: Tr): string | null {
  const n = normalizeQuery(q)
  if (!n) return null
  if (!QUERY_PART.test(n.name) || !QUERY_PART.test(n.value))
    return t
      ? t('sensors.scanIdent.err.query')
      : 'Name and value: 1 to 64 letters, digits or . _ ~ - each.'
  return null
}

/** Required identification without a header or a query parameter anywhere. */
export function requiredWithoutMarker(e: EffectiveIdentity): boolean {
  return e.required && e.headers.length === 0 && !e.query
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

function uaConfig(single: string | undefined, list: string[] | undefined): string[] {
  if (list && list.length > 0) return list
  const v = (single ?? '').trim()
  return v ? [v] : []
}

/**
 * The merge the platform makes for every job: the union of both layers'
 * headers (the organization wins a clash unless the platform enforces the
 * header); the winning layer's User-Agent setting whole; the query parameter
 * by the same order; required if either layer requires it.
 */
export function mergeIdentity(
  platform: PlatformIdentLayer | undefined,
  org: OrgIdentLayer
): EffectiveIdentity {
  const orgHeaders = org.headers
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
  const platUA = uaConfig(platform?.user_agent, platform?.user_agents)
  const orgUA = uaConfig(org.userAgent, org.userAgents)
  let userAgents: string[] = []
  let userAgentSource: IdentSource | undefined
  if (platUA.length > 0 && platform?.user_agent_enforced) {
    userAgents = platUA
    userAgentSource = 'platform_enforced'
  } else if (orgUA.length > 0) {
    userAgents = orgUA
    userAgentSource = 'organization'
  } else if (platUA.length > 0) {
    userAgents = platUA
    userAgentSource = 'platform'
  }
  const platQuery = normalizeQuery(platform?.query)
  const orgQuery = normalizeQuery(org.query)
  let query: IdentQuery | undefined
  let querySource: IdentSource | undefined
  if (platQuery && platform?.query_enforced) {
    query = platQuery
    querySource = 'platform_enforced'
  } else if (orgQuery) {
    query = orgQuery
    querySource = 'organization'
  } else if (platQuery) {
    query = platQuery
    querySource = 'platform'
  }
  const requiredBy: IdentSource[] = []
  if (platform?.identification_required) requiredBy.push('platform')
  if (org.required) requiredBy.push('organization')
  return {
    userAgent: userAgents[0] ?? '',
    userAgents,
    userAgentSource,
    headers,
    overridden,
    query,
    querySource,
    required: requiredBy.length > 0,
    requiredBy,
  }
}

/** The request lines a target receives, for the preview. */
export function previewLines(e: EffectiveIdentity, host = 'target.example'): string[] {
  const path = e.query ? `/?${e.query.name}=${e.query.value}` : '/'
  const lines = [`GET ${path} HTTP/1.1`, `Host: ${host}`]
  lines.push(`User-Agent: ${e.userAgent || '<tool default>'}`)
  for (const h of e.headers) lines.push(`${h.name}: ${h.value}`)
  return lines
}
