/**
 * Plans and limits (api docs/architecture/plans-and-limits.md): the limit keys
 * in display order, their English names, and how a limit reads.
 */

export const PLAN_NAMES = ['free', 'pro', 'enterprise'] as const
export type PlanName = (typeof PLAN_NAMES)[number]

export const PLAN_KEYS = [
  'seats',
  'assets',
  'sensors',
  'api_keys',
  'ci_trusts',
  'invites_per_day',
  'platform_scans_per_day',
  'platform_scans_concurrent',
  'free_teams_per_user',
] as const
export type PlanKey = (typeof PLAN_KEYS)[number]

/** -1: the limit does not apply. */
export const UNLIMITED = -1

export const PLAN_LABEL: Record<PlanName, string> = {
  free: 'Free',
  pro: 'Pro',
  enterprise: 'Enterprise',
}

export const PLAN_KEY_LABEL: Record<PlanKey, string> = {
  seats: 'Seats',
  assets: 'Assets',
  sensors: 'Sensors',
  api_keys: 'API keys',
  ci_trusts: 'CI trust configurations',
  invites_per_day: 'Invitations a day',
  platform_scans_per_day: 'Platform scans a day',
  platform_scans_concurrent: 'Concurrent platform scans',
  free_teams_per_user: 'Free organizations per person',
}

/** Keys that describe a person or the platform rather than this organization's usage. */
export const ORGANIZATION_KEYS: readonly PlanKey[] = PLAN_KEYS.filter(
  (k) => k !== 'free_teams_per_user'
)

export function isPlanKey(k: string): k is PlanKey {
  return (PLAN_KEYS as readonly string[]).includes(k)
}

export function isPlanName(p: string): p is PlanName {
  return (PLAN_NAMES as readonly string[]).includes(p)
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
