/**
 * Coverage level of a new scan (research/48 §6.7): how far a typed domain
 * reaches.
 *
 * - `host`: the names as typed.
 * - `subdomains`: each typed domain becomes `*.domain`, which the API
 *   resolves at the start of every run to the domain and every name the
 *   inventory then holds below it (RFC-068): names found later are scanned
 *   by the next run.
 * - `subdomains_ips`: plus the addresses those names resolve to, as the
 *   inventory recorded them now (a fixed list).
 *
 * The scope gate decides every target like any other (`POST /scope/check` in
 * the preview, the dispatch gate at each run). A name grant never becomes an
 * IP grant (RFC-054 §4.3): an address needs its own IP scope entry, so it
 * usually shows as refused with "add to scope" until one exists.
 */

export type CoverageLevel = 'host' | 'subdomains' | 'subdomains_ips'

export const COVERAGE_LEVELS: { id: CoverageLevel; label: string; hint: string }[] = [
  { id: 'host', label: 'This host only', hint: 'Exactly the names you entered.' },
  {
    id: 'subdomains',
    label: 'Host and its subdomains',
    hint: 'Scans each domain as *.domain: every run takes the subdomains your inventory holds at that time, including ones found later.',
  },
  {
    id: 'subdomains_ips',
    label: 'Host, subdomains and their IPs',
    hint: 'Also adds the addresses those names resolve to today. Each address needs its own scope entry.',
  },
]

/** At most this many targets are added by an expansion. */
export const MAX_EXPANDED_TARGETS = 500

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/
const DNS_NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i

/** The DNS name a target stands for (a URL's host), or "" for an address. */
export function domainRoot(target: string): string {
  let t = target.trim().toLowerCase()
  if (!t) return ''
  if (/^https?:\/\//.test(t)) {
    try {
      t = new URL(t).hostname
    } catch {
      return ''
    }
  }
  t = t.replace(/^\*\./, '').replace(/\.$/, '')
  const colon = t.lastIndexOf(':')
  if (colon > 0 && /^\d+$/.test(t.slice(colon + 1))) t = t.slice(0, colon)
  if (IPV4.test(t) || t.includes(':')) return ''
  return DNS_NAME.test(t) ? t : ''
}

/** Unique domain roots of the targets, dropping a root already under another. */
export function domainRoots(targets: string[]): string[] {
  const roots = [...new Set(targets.map(domainRoot).filter(Boolean))].sort(
    (a, b) => a.length - b.length
  )
  const kept: string[] = []
  for (const r of roots) {
    if (!kept.some((k) => r === k || r.endsWith(`.${k}`))) kept.push(r)
  }
  return kept
}

/** Whether `name` sits strictly below `root`. */
export function isBelow(name: string, root: string): boolean {
  const n = name.trim().toLowerCase().replace(/\.$/, '')
  return n.endsWith(`.${root}`) && DNS_NAME.test(n)
}

/**
 * The property keys an address can sit under: the canonical `ip_addresses`
 * (ingest folds every synonym into it) first, then the synonyms a row that
 * has not been normalised yet may still carry.
 */
const ADDRESS_KEYS = [
  'ip_addresses',
  'ip',
  'ips',
  'ip_address',
  'resolved_ip',
  'resolved_ips',
  'addresses',
] as const

/** Hex digits, dots and colons only: an IPv4 or IPv6 address, not free text. */
const ADDRESS_SHAPE = /^[0-9a-f:.]+$/i

/** The addresses an inventory asset recorded (properties.ip_addresses or a synonym). */
export function resolvedIps(properties: Record<string, unknown> | undefined): string[] {
  if (!properties) return []
  const out: string[] = []
  const take = (x: unknown) => {
    if (typeof x !== 'string') return
    const v = x.trim()
    if (v.length > 0 && v.length < 64 && ADDRESS_SHAPE.test(v) && !out.includes(v)) out.push(v)
  }
  for (const key of ADDRESS_KEYS) {
    const v = properties[key]
    if (Array.isArray(v)) v.forEach(take)
    else take(v)
  }
  return out
}

/** The inventory names at or below the typed domains' roots. */
export function namesUnder(typed: string[], inventory: InventoryName[]): InventoryName[] {
  const roots = domainRoots(typed)
  return inventory.filter((a) => roots.some((r) => isBelow(a.name, r) || a.name === r))
}

export interface InventoryName {
  name: string
  properties?: Record<string, unknown>
}

/**
 * The addresses the `subdomains_ips` level adds to `typed`, from inventory
 * names found under each root (already fetched). Subdomains themselves are
 * not listed: the `*.domain` target covers them at every run. Never repeats a
 * typed target; capped.
 */
export function expandTargets(
  typed: string[],
  level: CoverageLevel,
  inventory: InventoryName[]
): string[] {
  if (level !== 'subdomains_ips') return []
  const seen = new Set(typed.map((t) => t.trim().toLowerCase()))
  const out: string[] = []
  const add = (v: string) => {
    const k = v.trim().toLowerCase()
    if (!k || seen.has(k) || out.length >= MAX_EXPANDED_TARGETS) return
    seen.add(k)
    out.push(v.trim())
  }
  for (const a of namesUnder(typed, inventory)) for (const ip of resolvedIps(a.properties)) add(ip)
  return out
}
