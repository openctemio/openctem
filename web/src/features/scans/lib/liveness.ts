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

/** The mode a scan runs: a saved scan without one sweeps; a new one defaults to liveness. */
export function effectiveCidrMode(mode: CidrMode | undefined, saved: boolean): CidrMode {
  return mode ?? (saved ? 'sweep' : 'liveness')
}
