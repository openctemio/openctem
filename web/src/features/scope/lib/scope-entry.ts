/**
 * Scope entries (RFC-054 §4.1, §6.1): what an entry covers, its state and its
 * expiry, in words. Pure helpers shared by the Scope page, the entry dialog
 * and the scan dialog.
 */

import type { PillTone } from '@/features/shared'
import type { ApiScopeTarget } from '../api/scope-api.types'

export type ScopeEntryStatus = 'active' | 'pending' | 'inactive' | 'rejected' | 'expired'

export const SCOPE_ENTRY_STATUSES: ScopeEntryStatus[] = [
  'active',
  'pending',
  'expired',
  'inactive',
  'rejected',
]

export const SCOPE_ENTRY_STATUS_LABEL: Record<ScopeEntryStatus, string> = {
  active: 'Active',
  pending: 'Pending approval',
  inactive: 'Inactive',
  rejected: 'Rejected',
  expired: 'Expired',
}

export const SCOPE_ENTRY_STATUS_TONE: Record<ScopeEntryStatus, PillTone> = {
  active: 'success',
  pending: 'warning',
  inactive: 'muted',
  rejected: 'destructive',
  expired: 'muted',
}

export const SCOPE_ENTRY_STATUS_HINT: Record<ScopeEntryStatus, string> = {
  active: 'Authorizes probes now.',
  pending: 'Authorizes nothing until it has its approvals.',
  inactive: 'Deactivated: authorizes nothing.',
  rejected: 'Declined: never took effect.',
  expired: 'Its time ran out: authorizes nothing.',
}

export function entryStatus(e: Pick<ApiScopeTarget, 'status'>): ScopeEntryStatus {
  const s = e.status ?? ''
  return (SCOPE_ENTRY_STATUSES as string[]).includes(s) ? (s as ScopeEntryStatus) : 'inactive'
}

/** The apex of a wildcard pattern: "*.x" and "**.x" -> "x"; anything else "". */
export function wildcardApex(pattern: string): string {
  const p = pattern.trim()
  if (p.startsWith('**.')) return p.slice(3)
  if (p.startsWith('*.')) return p.slice(2)
  return ''
}

/**
 * What an entry covers, in words (§4.1). `covers` is the server's own
 * reading (name, domain_and_subdomains, addresses, pattern); the pattern is
 * used when the server sent none.
 */
export function coversText(e: { pattern?: string; covers?: string; target_type?: string }): string {
  const pattern = (e.pattern ?? '').trim()
  const apex = wildcardApex(pattern)
  const kind = e.target_type ?? ''
  const covers =
    e.covers ||
    (apex
      ? 'domain_and_subdomains'
      : kind === 'domain' || kind === 'subdomain'
        ? 'name'
        : kind === 'ip_address' || kind === 'ip_range' || kind === 'cidr'
          ? 'addresses'
          : '')
  switch (covers) {
    case 'domain_and_subdomains':
      return apex ? `${apex} and every name below it` : 'The domain and every name below it'
    case 'name':
      return `${pattern} only`
    case 'addresses':
      return pattern.includes('/') || pattern.includes('-')
        ? `Every address in ${pattern}`
        : `${pattern} only`
    default:
      return pattern ? `Names matching ${pattern}` : ''
  }
}

/** Whole days until `iso` from `now` (ceil; negative once past). */
export function daysUntil(iso: string, now: number = Date.now()): number {
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return 0
  return Math.ceil((t - now) / 86_400_000)
}

/** "Expires in 3 days", "Expires today", "Expired 2 days ago", "Permanent". */
export function expiryText(expiresAt: string | undefined | null, now: number = Date.now()): string {
  if (!expiresAt) return 'Permanent'
  const t = Date.parse(expiresAt)
  if (Number.isNaN(t)) return 'Permanent'
  const ms = t - now
  if (ms <= 0) {
    const ago = Math.floor(-ms / 86_400_000)
    return ago === 0 ? 'Expired today' : `Expired ${ago} ${ago === 1 ? 'day' : 'days'} ago`
  }
  const hours = Math.ceil(ms / 3_600_000)
  if (hours < 24) return `Expires in ${hours} ${hours === 1 ? 'hour' : 'hours'}`
  const days = Math.ceil(ms / 86_400_000)
  return `Expires in ${days} ${days === 1 ? 'day' : 'days'}`
}

export const TIER_LABEL: Record<string, string> = {
  t0: 'T0 passive',
  t1: 'T1 safe active',
  t2: 'T2 intrusive',
}

export const TIER_HINT: Record<string, string> = {
  t0: 'Passive only: DNS, certificates, public sources. Nothing is sent to the target.',
  t1: 'Safe active checks: port scans, HTTP probes, non-intrusive templates.',
  t2: 'Intrusive tests that may change state. Needs an expiry, an approval and a verified domain.',
}

/** Approvals still needed, never below 0. */
export function approvalsMissing(e: Pick<ApiScopeTarget, 'approvals' | 'approvals_required'>) {
  return Math.max(0, (e.approvals_required ?? 0) - (e.approvals?.length ?? 0))
}

/**
 * Whether `userId` may approve `e`: it is pending, they did not create
 * (request or widen) it, and they have not approved it yet. The server
 * decides; this only hides a button that would be refused.
 */
export function canApproveEntry(
  e: Pick<ApiScopeTarget, 'status' | 'created_by' | 'approvals'>,
  userId: string | undefined
): boolean {
  if (entryStatus(e) !== 'pending' || !userId) return false
  if (e.created_by === userId) return false
  return !(e.approvals ?? []).some((a) => a.user_id === userId)
}

/** The scope entry pattern a domain-coverage choice stands for. */
export function patternForCoverage(name: string, coverage: 'name' | 'subdomains'): string {
  const host = wildcardApex(name) || name.trim()
  return coverage === 'subdomains' ? `*.${host}` : host
}
