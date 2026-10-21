/**
 * Navigation through a task's findings: which finding is before / after the
 * one shown, and which open one to move to after an action. Pure, so the
 * table, the drawer and the keyboard handler agree.
 */

/** Statuses that still need work from the task's owner. */
export const WORK_STATUSES: ReadonlySet<string> = new Set(['new', 'confirmed', 'in_progress'])

export interface NavPosition {
  /** 1-based position of the finding in the list, 0 when it is not in it. */
  index: number
  total: number
  prev: string | null
  next: string | null
}

export function positionOf(order: readonly string[], id: string | null): NavPosition {
  const i = id ? order.indexOf(id) : -1
  return {
    index: i + 1,
    total: order.length,
    prev: i > 0 ? order[i - 1] : null,
    next: i >= 0 && i < order.length - 1 ? order[i + 1] : null,
  }
}

/** The id `delta` places from `id`, clamped to the list; the first when `id` is not in it. */
export function stepFinding(order: readonly string[], id: string | null, delta: 1 | -1) {
  if (order.length === 0) return null
  const i = id ? order.indexOf(id) : -1
  if (i < 0) return order[delta === 1 ? 0 : order.length - 1]
  return order[Math.min(order.length - 1, Math.max(0, i + delta))]
}

/**
 * The next finding that still needs work after `id` (wrapping once), never
 * `id` itself; null when none is left.
 */
export function nextWorkFinding(
  order: readonly string[],
  statusOf: (id: string) => string | undefined,
  id: string
): string | null {
  const i = order.indexOf(id)
  for (let step = 1; step < order.length; step++) {
    const cand = order[(i + step + order.length) % order.length]
    const s = statusOf(cand)
    if (s && WORK_STATUSES.has(s)) return cand
  }
  return null
}

/** The task a finding page was opened from: `?from=task:{id}`. */
export function taskFromParam(from: string | null | undefined): string | null {
  const m = /^task:([0-9a-f-]{8,64})$/i.exec(from ?? '')
  return m ? m[1] : null
}
