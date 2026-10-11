/**
 * Typed attack-surface changes (RFC-080): the kinds, their order and the
 * request URL of GET /api/v1/easm/changes.
 */

/** Every change kind, riskiest first (the API's order). */
export const CHANGE_KINDS = [
  'dns_dangling',
  'exposure_new',
  'port_opened',
  'host_added',
  'cert_expiring',
  'cert_changed',
  'dns_changed',
  'tech_changed',
  'port_closed',
  'host_removed',
] as const

export type ChangeKind = (typeof CHANGE_KINDS)[number]

export function isChangeKind(v: string): v is ChangeKind {
  return (CHANGE_KINDS as readonly string[]).includes(v)
}

/** Windows the page offers, in days (the API allows at most 31). */
export const CHANGE_WINDOWS = [7, 14, 30] as const

export interface ChangeQuery {
  /** An explicit window (a digest link); wins over days. */
  from?: string
  to?: string
  days: number
  kinds: ChangeKind[]
}

/** Builds the request URL of one page. now is injectable for tests. */
export function changesRequestUrl(q: ChangeQuery, cursor?: string, now: Date = new Date()): string {
  const p = new URLSearchParams()
  if (q.from && q.to) {
    p.set('from', q.from)
    p.set('to', q.to)
  } else {
    const days = Math.min(Math.max(q.days, 1), 31)
    p.set('from', new Date(now.getTime() - days * 86_400_000).toISOString())
  }
  if (q.kinds.length > 0) p.set('kind', q.kinds.join(','))
  p.set('limit', '50')
  if (cursor) p.set('cursor', cursor)
  return `/api/v1/easm/changes?${p.toString()}`
}

/** A valid RFC 3339 time from a URL parameter, or undefined. */
export function parseTime(v: string | null): string | undefined {
  if (!v) return undefined
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
}
