/**
 * The scope entry that covers an inventory asset, for "Add to scope" on a
 * selection (RFC-054 §14). Always an exact entry: a name covers that name, an
 * address that address; never a wildcard (widening to every subdomain stays a
 * deliberate choice in the entry dialog). A URL or a service is covered by
 * its host. Private addresses and internal names are routed by scan zones,
 * and repositories or cloud resources need no entry, so they are skipped with
 * a reason. The server still decides: this only builds the request.
 */

import type { BulkScopeTargetItemInput } from '../api/scope-api.types'
import { detectScopeKind } from '../components/scope-target-type'

export type ScopeSkipReason = 'internal' | 'no_entry_needed' | 'unrecognized'

export type ScopeItemForAsset =
  { item: BulkScopeTargetItemInput; skip?: undefined } | { item?: undefined; skip: ScopeSkipReason }

/** The host of a URL, of host:port(:proto|/proto), of [v6]:port, else the value. */
export function hostOf(raw: string): string {
  const v = raw.trim()
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) {
    try {
      return new URL(v).hostname.replace(/^\[|\]$/g, '')
    } catch {
      return ''
    }
  }
  const v6 = /^\[([0-9a-f:.]+)\](?::\d+)?(?:[:/][a-z]+)?$/i.exec(v)
  if (v6) return v6[1]
  // host:443, host:443:tcp, host:443/tcp (a bare IPv6 has many colons: kept).
  const svc = /^([^:/\s]+):\d{1,5}(?:[:/][a-z]+)?$/i.exec(v)
  if (svc) return svc[1]
  return v
}

const PRIVATE_V4 = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^0\./,
]

/** A private, loopback, link-local or CGNAT address, or an internal DNS name. */
export function isInternalHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '')
  if (PRIVATE_V4.some((re) => re.test(h))) return true
  if (h.includes(':')) {
    return h === '::1' || h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')
  }
  return (
    h === 'localhost' ||
    h.endsWith('.localhost') ||
    h.endsWith('.local') ||
    h.endsWith('.internal') ||
    h.endsWith('.lan')
  )
}

export function scopeItemForAsset(name: string): ScopeItemForAsset {
  const raw = name.trim()
  if (!raw) return { skip: 'unrecognized' }
  const direct = detectScopeKind(raw)
  if (direct === 'repository' || direct === 'cloud_account') return { skip: 'no_entry_needed' }
  if (direct === 'ip_range') {
    if (isInternalHost(raw.split(/[/-]/)[0])) return { skip: 'internal' }
    return { item: { target_type: 'ip_range', pattern: raw } }
  }
  const host = hostOf(raw)
  if (!host) return { skip: 'unrecognized' }
  if (isInternalHost(host)) return { skip: 'internal' }
  const kind = detectScopeKind(host)
  if (kind === 'ip_address') return { item: { target_type: 'ip_address', pattern: host } }
  if (kind === 'domain' && !host.startsWith('*')) {
    return { item: { target_type: 'domain', pattern: host.toLowerCase().replace(/\.$/, '') } }
  }
  return { skip: 'unrecognized' }
}

/** Items for a selection, de-duplicated, and how many were skipped and why. */
export function scopeItemsForAssets(names: string[]): {
  items: BulkScopeTargetItemInput[]
  skipped: Partial<Record<ScopeSkipReason, number>>
} {
  const seen = new Set<string>()
  const items: BulkScopeTargetItemInput[] = []
  const skipped: Partial<Record<ScopeSkipReason, number>> = {}
  for (const n of names) {
    const r = scopeItemForAsset(n)
    if (r.skip) {
      skipped[r.skip] = (skipped[r.skip] ?? 0) + 1
      continue
    }
    const key = `${r.item.target_type}:${r.item.pattern}`
    if (seen.has(key)) continue
    seen.add(key)
    items.push(r.item)
  }
  return { items, skipped }
}

/**
 * The entry dialog's starting draft for one asset's "Add to scope": the same
 * entry the bulk action would add (a service or URL by its host), else the
 * asset's own name with the given kind so the dialog explains what it cannot
 * cover.
 */
export function scopeDraftForAsset(
  name: string,
  fallbackType?: BulkScopeTargetItemInput['target_type']
): { pattern: string; target_type?: BulkScopeTargetItemInput['target_type'] } {
  const r = scopeItemForAsset(name)
  if (r.item) return { pattern: r.item.pattern, target_type: r.item.target_type }
  return { pattern: name, target_type: fallbackType }
}
