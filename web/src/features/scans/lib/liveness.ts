/**
 * Live hosts first for address ranges (RFC-088 step 6). A new scan with a
 * range defaults to it when its scan can run it; a saved scan keeps its mode
 * until a person switches it (decision A1), so the console only suggests it.
 */

import type { ScanWorkflow } from '@/lib/api'
import type { CidrMode } from './dynamic-targets'

/** The capability of a Host discovery step. */
export const HOST_DISCOVERY = 'discover.hosts'

/**
 * Whether a scan can run live hosts first: a single scanner always can; a
 * workflow needs a Host discovery step. undefined while the workflow loads.
 */
export function canFindLiveHosts(
  mode: 'single' | 'workflow',
  workflow: Pick<ScanWorkflow, 'steps'> | undefined | null
): boolean | undefined {
  if (mode === 'single') return true
  if (!workflow) return undefined
  return (workflow.steps ?? []).some((s) => (s.capabilities ?? []).includes(HOST_DISCOVERY))
}

/**
 * The mode a scan runs, by the rule the API applies on save: a chosen mode is
 * kept; a saved scan without one sweeps; a new scan finds live hosts first
 * unless its scan cannot (a workflow without Host discovery), then it sweeps.
 * livenessAvailable undefined (the workflow still loading) reads as able.
 * The choice shown, the summary and the request all read this one answer.
 */
export function effectiveCidrMode(
  mode: CidrMode | undefined,
  saved: boolean,
  livenessAvailable?: boolean
): CidrMode {
  if (mode) return mode
  return saved || livenessAvailable === false ? 'sweep' : 'liveness'
}
