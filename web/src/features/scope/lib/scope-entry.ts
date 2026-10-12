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
        ? `every address in ${pattern}`
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

/** The tools each tier lets run (the stage catalog's default tools). */
export const TIER_TOOLS: Record<string, string> = {
  t0: 'subfinder, dnsx',
  t1: 'naabu, httpx, katana, nuclei (safe templates)',
  t2: 'ZAP web application scans that send attack payloads',
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
  if (e.created_by?.id === userId) return false
  return !(e.approvals ?? []).some((a) => a.user_id === userId)
}

/** The scope entry pattern a domain-coverage choice stands for. */
export function patternForCoverage(name: string, coverage: 'name' | 'subdomains'): string {
  const host = wildcardApex(name) || name.trim()
  return coverage === 'subdomains' ? `*.${host}` : host
}

/**
 * The expiry bound of an entry of `tier` (RFC-054 §12.4): intrusive (t2)
 * entries follow the owner's t2 limit, every other entry the one-off limit.
 * `permanent` says whether the entry may have no expiry at all.
 */
export function expiryBoundFor(
  tier: string,
  settings:
    { one_off_max_days?: number; t2_max_days?: number; t2_permanent_allowed?: boolean } | undefined
): { maxDays: number; permanent: boolean } {
  if (tier === 't2') {
    return {
      maxDays: Math.max(1, settings?.t2_max_days ?? 30),
      permanent: settings?.t2_permanent_allowed ?? false,
    }
  }
  return { maxDays: Math.max(1, settings?.one_off_max_days ?? 7), permanent: true }
}

/** The durations offered for an expiring entry, in days. */
export const DURATION_PRESET_DAYS = [7, 30, 90, 365] as const

/**
 * What a new or edited entry may last, for its tier and the caller:
 * - permanent: allowed, forbidden (offered disabled with the reason: an
 *   owner may allow it) or hidden (a member request always expires);
 * - expiring: whether an expiry is allowed at all;
 * - maxDays: the longest expiry, in days.
 */
export interface DurationPolicy {
  maxDays: number
  permanent: 'allowed' | 'forbidden' | 'hidden'
  expiring: boolean
}

type DurationSettings = {
  one_off_targets?: string
  one_off_max_days?: number
  t2_max_days?: number
  t2_permanent_allowed?: boolean
}

export function durationPolicy(
  tier: string,
  settings: DurationSettings | undefined,
  opts: { isRequest: boolean }
): DurationPolicy {
  const { maxDays, permanent } = expiryBoundFor(tier, settings)
  if (opts.isRequest) return { maxDays, permanent: 'hidden', expiring: true }
  if (tier === 't2') {
    return { maxDays, permanent: permanent ? 'allowed' : 'forbidden', expiring: true }
  }
  return {
    maxDays,
    permanent: 'allowed',
    expiring: (settings?.one_off_targets ?? 'admins_and_requests') !== 'disabled',
  }
}

/** How long an entry lasts: no expiry, a number of days from now, or as it is. */
export type DurationChoice =
  { kind: 'permanent' } | { kind: 'days'; days: number; custom?: boolean } | { kind: 'keep' }

/** The preset durations under the limit, and the limit itself when it is not one. */
export function presetDays(maxDays: number): number[] {
  const out: number[] = DURATION_PRESET_DAYS.filter((d) => d <= maxDays)
  if (!out.includes(maxDays)) out.push(maxDays)
  return out
}

/** The longest duration the policy allows: permanent when allowed, else its day limit. */
export function defaultDuration(p: DurationPolicy): DurationChoice {
  if (p.permanent === 'allowed' || !p.expiring) return { kind: 'permanent' }
  return { kind: 'days', days: p.maxDays }
}

/** Whether the policy allows the choice. */
export function durationAllowed(c: DurationChoice, p: DurationPolicy): boolean {
  if (c.kind === 'keep') return true
  if (c.kind === 'permanent') return p.permanent === 'allowed'
  return p.expiring && c.days >= 1 && c.days <= p.maxDays
}

/** The user's choice while the policy allows it, otherwise the default. */
export function resolveDuration(c: DurationChoice | null, p: DurationPolicy): DurationChoice {
  return c && durationAllowed(c, p) ? c : defaultDuration(p)
}

const DAY_MS = 86_400_000

function startOfDay(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate())
}

/** The day an entry expiring in `days` ends on. */
export function expiryDateFor(days: number, now: Date = new Date()): Date {
  const d = startOfDay(now)
  d.setDate(d.getDate() + days)
  return d
}

/** "YYYY-MM-DD", for a date input. */
export function isoDay(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

/** Whole days from today to the "YYYY-MM-DD" day (0 when it does not parse). */
export function daysToDay(day: string, now: Date = new Date()): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day)
  if (!m) return 0
  const target = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]))
  return Math.round((target.getTime() - startOfDay(now).getTime()) / DAY_MS)
}

/** "9 Nov 2026" in the reader's language. */
export function formatDay(d: Date, locale = 'en'): string {
  return new Intl.DateTimeFormat(locale === 'en' ? 'en-GB' : locale, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  }).format(d)
}
