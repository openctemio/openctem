import type { Finding } from '@/features/findings/types/finding.types'
import { FINDINGS_CLOSED_STATUSES } from './list-defaults'

const CLOSED = new Set<string>(FINDINGS_CLOSED_STATUSES)

/**
 * The tone of a finding row in a list: 'dim' for rows that are not the work
 * of the moment (priority P3, or closed: fixed or dispositioned as false
 * positive, accepted or duplicate). Dim rows change colour only, never
 * opacity, so their text keeps its contrast.
 */
export function findingRowTone(f: Pick<Finding, 'priorityClass' | 'status'>): 'dim' | undefined {
  if (f.priorityClass === 'P3') return 'dim'
  if (f.status && CLOSED.has(f.status)) return 'dim'
  return undefined
}
