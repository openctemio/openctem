/**
 * Scope entries as scan targets, for the "From scope" source of the target
 * picker: a wildcard entry becomes a `*.domain` target (re-resolved at every
 * run), a domain, an address or a CIDR is itself. Entries that are not a
 * single target (a name pattern such as `api-*.example.com`, an address span
 * `a-b`) are listed but not pickable. Only in-scope entries are offered; out
 * of scope entries live in another list and are never read here. Picking is
 * a convenience: every target still passes the server's scope check.
 */

import { wildcardApex } from '@/features/scope/lib/scope-entry'
import { classifyTarget } from './target-format'

/** The scope entry kinds a scan can take as a target. */
export const PICKABLE_SCOPE_TYPES = ['domain', 'subdomain', 'ip_address', 'ip_range'] as const

/** An entry expiring within this many days is flagged. */
export const SCOPE_EXPIRY_WARN_DAYS = 7

export interface ScopeEntryLike {
  pattern?: string
  covers?: string
}

/** The target an entry becomes, or null when it is not one target. */
export function scopeEntryTarget(e: ScopeEntryLike): string | null {
  const pattern = (e.pattern ?? '').trim()
  if (!pattern) return null
  const apex = wildcardApex(pattern)
  if (apex) {
    const c = classifyTarget(apex)
    return c.kind === 'domain' ? `*.${c.value}` : null
  }
  const c = classifyTarget(pattern)
  if (c.kind === 'domain') {
    return e.covers === 'domain_and_subdomains' ? `*.${c.value}` : c.value
  }
  if (c.kind === 'ipv4' || c.kind === 'ipv6' || c.kind === 'cidr') return c.value
  return null
}

/** Whole days until the entry expires (ceil), or null for a permanent one. */
export function expiresInDays(
  expiresAt: string | null | undefined,
  now = Date.now()
): number | null {
  if (!expiresAt) return null
  const t = Date.parse(expiresAt)
  if (Number.isNaN(t)) return null
  return Math.max(0, Math.ceil((t - now) / 86_400_000))
}
