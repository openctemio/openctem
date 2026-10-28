/**
 * Skipped targets, grouped by reason: the routing preview (`skipped`) and a
 * run's dispatch report (`dispatch.skipped`) send the same groups.
 * Contract: api/docs/architecture/scan-targets.md ("Skipped targets").
 */

import type { SkipGroup } from '@/lib/api/scan-types'

export type { SkipGroup, SkipTone } from '@/lib/api/scan-types'

/** Reasons the console has words for; anything else reads as "other". */
export const SKIP_REASONS = [
  'unresolved',
  'not_resolving',
  'excluded',
  'archived',
  'incompatible_type',
  'out_of_scope',
  'ownership_unconfirmed',
  'wildcard_only',
  'tier_exceeded',
  'internal_outside_zones',
  'outside_zones',
  'partly_covered',
  'outside_selected_zone',
  'deny_list',
  'zone_no_sensor',
  'sensor_policy',
  'invalid',
] as const

export type SkipReason = (typeof SKIP_REASONS)[number] | 'other'

export function skipReasonKey(reason: string): SkipReason {
  return (SKIP_REASONS as readonly string[]).includes(reason) ? (reason as SkipReason) : 'other'
}

/** Every target the groups skip. */
export function skippedTotal(groups: SkipGroup[]): number {
  return groups.reduce((n, g) => n + g.count, 0)
}

/** True when a group asks for a fix (the summary then says so). */
export function needsAttention(groups: SkipGroup[]): boolean {
  return groups.some((g) => g.tone === 'warning' && g.count > 0)
}

/** Names that do not resolve: the old run record has a reason text only. */
const UNRESOLVED_TEXT = 'does not resolve in DNS'

/**
 * Groups for a run recorded before the API sent them: the listed uncovered
 * targets by reason text, the rest of the count as "other".
 */
export function groupsFromUncovered(
  uncovered: { target: string; reason: string }[],
  total: number
): SkipGroup[] {
  const unresolved = uncovered.filter((u) => u.reason.includes(UNRESOLVED_TEXT))
  const other = uncovered.filter((u) => !u.reason.includes(UNRESOLVED_TEXT))
  const out: SkipGroup[] = []
  const rest = Math.max(total - uncovered.length, 0)
  if (unresolved.length > 0) {
    out.push({
      reason: 'unresolved',
      tone: 'info',
      count: unresolved.length + (other.length === 0 ? rest : 0),
      targets: unresolved.map((u) => u.target),
    })
  }
  if (other.length > 0 || (unresolved.length === 0 && rest > 0)) {
    out.push({
      reason: 'other',
      tone: 'warning',
      count: other.length + rest,
      targets: other.map((u) => u.target),
    })
  }
  return out.sort((a, b) => b.count - a.count)
}

/**
 * Server warnings the skip groups already say ("x not scanned: ...",
 * "N name(s) left out: ...", "N target(s) were skipped: ..."), so they are
 * not repeated under Warnings.
 */
const SKIP_WARNING =
  /( not scanned: )|^\d+ (name\(s\) left out|target\(s\) were skipped|internal address target\(s\) were skipped|archived asset\(s\)|asset\(s\) in the group\(s\) were skipped)/

export function isSkipWarning(warning: string): boolean {
  return SKIP_WARNING.test(warning)
}
