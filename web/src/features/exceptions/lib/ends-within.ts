import type { SuppressionRule } from '../types'

const DAY = 24 * 60 * 60 * 1000

/** An approved rule that ends within `days` from `now` (the list's "Ending in" counts and filter). */
export function endsWithin(rule: SuppressionRule, days: number, now: number): boolean {
  if (rule.status !== 'approved' || !rule.expires_at) return false
  const end = Date.parse(rule.expires_at)
  return !Number.isNaN(end) && end >= now && end - now <= days * DAY
}
