/**
 * Comparison logic shared by the visualizations: how a change reads (better or
 * worse, by the figure's polarity), and how a value stands against a target.
 * Kept free of React so it is tested on its own.
 */
import type { MetricTarget, Polarity, StageState, WidgetState } from './types'
import { accessStateOf } from '@/lib/api/access-state'

export type DeltaTone = 'better' | 'worse' | 'flat' | 'neutral'

/**
 * How a change reads. A drop in open findings is better (down_good), a rise in
 * the share within SLA is better (up_good); a neutral figure has no tone.
 */
export function deltaTone(delta: number | null | undefined, polarity: Polarity): DeltaTone {
  if (delta == null || !Number.isFinite(delta)) return 'neutral'
  if (delta === 0) return 'flat'
  if (polarity === 'neutral') return 'neutral'
  const up = delta > 0
  return (polarity === 'up_good') === up ? 'better' : 'worse'
}

/** The change from previous to current, or null when either is unknown. */
export function changeOf(
  current: number | null | undefined,
  previous: number | null | undefined
): number | null {
  if (current == null || previous == null) return null
  if (!Number.isFinite(current) || !Number.isFinite(previous)) return null
  return current - previous
}

function meets(value: number, op: MetricTarget['op'], bound: number): boolean {
  switch (op) {
    case '<=':
      return value <= bound
    case '>=':
      return value >= bound
    case '<':
      return value < bound
    case '>':
      return value > bound
    case '=':
      return value === bound
  }
}

export type TargetStatus = 'met' | 'near' | 'missed' | 'unmeasured'

/**
 * Where a value stands against its target: met, near (inside the optional
 * warn bound, same operator) or missed. A value that was not measured is
 * never "met".
 */
export function targetStatus(
  value: number | null | undefined,
  target: MetricTarget | null | undefined
): TargetStatus | null {
  if (!target) return null
  if (value == null || !Number.isFinite(value)) return 'unmeasured'
  if (meets(value, target.op, target.value)) return 'met'
  if (target.warn != null && meets(value, target.op, target.warn)) return 'near'
  return 'missed'
}

/** The stage colour state for a target status. */
export function stageStateOf(status: TargetStatus | null): StageState {
  switch (status) {
    case 'met':
      return 'good'
    case 'near':
      return 'warn'
    case 'missed':
      return 'crit'
    default:
      return 'unmeasured'
  }
}

/** Stale when older than twice the refresh interval, or the last refresh failed. */
export function isStale(
  asOf: string | Date | null | undefined,
  refreshIntervalMs: number | null | undefined,
  lastRefreshFailed = false,
  now: Date = new Date()
): boolean {
  if (lastRefreshFailed) return true
  if (!asOf || !refreshIntervalMs || refreshIntervalMs <= 0) return false
  const d = typeof asOf === 'string' ? new Date(asOf) : asOf
  if (Number.isNaN(d.getTime())) return false
  return now.getTime() - d.getTime() > 2 * refreshIntervalMs
}

/** The widget state for a failed read: a refusal is not a failure. */
export function stateFromError(error: unknown): WidgetState | undefined {
  const access = accessStateOf(error)
  if (access === 'no_access') return 'no_access'
  if (access === 'module_off') return 'module_off'
  if (access === 'failed') return 'error'
  return undefined
}
