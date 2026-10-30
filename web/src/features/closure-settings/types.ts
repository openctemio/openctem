/** How the platform closes findings without a person (GET/PUT /organization/settings/closure). */
export type ClosingMode = 'auto' | 'review' | 'off'

export const CLOSING_MODES: ClosingMode[] = ['auto', 'review', 'off']

export interface ClosureSettings {
  /** In force; empty means review (organizations created before the setting). */
  mode?: ClosingMode | ''
  critical_auto_close: boolean
  /** A loosening chosen less than 24 hours ago, taking effect at pending_at. */
  pending_mode?: ClosingMode
  pending_critical_auto_close?: boolean
  pending_at?: string
}

/** The mode in force (unset reads as review). */
export function effectiveMode(s: Pick<ClosureSettings, 'mode'>): ClosingMode {
  return s.mode ? s.mode : 'review'
}

const RANK: Record<ClosingMode, number> = { off: 0, review: 1, auto: 2 }

/** Whether going from current to next lets the platform close more alone (it then waits 24 hours). */
export function loosens(
  current: Pick<ClosureSettings, 'mode' | 'critical_auto_close'>,
  next: Pick<ClosureSettings, 'mode' | 'critical_auto_close'>
): boolean {
  if (RANK[effectiveMode(next)] > RANK[effectiveMode(current)]) return true
  return next.critical_auto_close && !current.critical_auto_close
}
