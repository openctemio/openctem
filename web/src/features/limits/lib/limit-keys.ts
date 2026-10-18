/**
 * Limits (api docs/architecture/limits.md): the limit keys in display order,
 * their English names, and how a limit reads. -1 is unlimited.
 */

export const LIMIT_KEYS = [
  'seats',
  'assets',
  'sensors',
  'api_keys',
  'ci_trusts',
  'invites_per_day',
  'platform_scans_per_day',
  'platform_scans_concurrent',
  'findings',
  'lifecycle_sub_statuses',
  'lifecycle_schemes',
  'storage_mb',
  'orgs_per_user',
] as const
export type LimitKey = (typeof LIMIT_KEYS)[number]

/** Keys that can be set for one organization (orgs_per_user is per person). */
export const ORGANIZATION_LIMIT_KEYS: readonly LimitKey[] = LIMIT_KEYS.filter(
  (k) => k !== 'orgs_per_user'
)

/** -1: the limit does not apply. */
export const UNLIMITED = -1

/** English names; the translated ones are limits.key.<key>. */
export const LIMIT_KEY_LABEL: Record<LimitKey, string> = {
  seats: 'Seats',
  assets: 'Assets',
  sensors: 'Sensors',
  api_keys: 'API keys',
  ci_trusts: 'CI trust configurations',
  invites_per_day: 'Invitations a day',
  platform_scans_per_day: 'Platform scans a day',
  platform_scans_concurrent: 'Concurrent platform scans',
  findings: 'Findings',
  lifecycle_sub_statuses: 'Finding sub-statuses',
  lifecycle_schemes: 'Finding lifecycles',
  storage_mb: 'Storage (MiB)',
  orgs_per_user: 'Organizations per person',
}

export function isLimitKey(k: string | undefined): k is LimitKey {
  return !!k && (LIMIT_KEYS as readonly string[]).includes(k)
}

/** "500", or `unlimited` for -1 (or a missing limit). */
export function formatLimit(limit: number | undefined, unlimited: string): string {
  return limit === undefined || limit === UNLIMITED ? unlimited : String(limit)
}

/** Share of the limit used, 0..100; null when unlimited or the limit is 0. */
export function usagePercent(used: number, limit: number | undefined): number | null {
  if (limit === undefined || limit === UNLIMITED || limit <= 0) return null
  return Math.min(100, Math.round((used / limit) * 100))
}

/** Empty = unlimited (-1); otherwise a whole number of 0 or more; null when invalid. */
export function parseLimit(v: string): number | null {
  const s = v.trim()
  if (s === '') return UNLIMITED
  if (!/^\d+$/.test(s)) return null
  const n = Number(s)
  return Number.isSafeInteger(n) ? n : null
}
