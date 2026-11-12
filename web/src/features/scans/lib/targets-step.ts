/**
 * Whether the Targets step lets the wizard go on: Next is gated only when
 * nothing can run. Pure: the readiness is the server's scope check, read
 * through scanReadiness; nothing here decides scope.
 */

import type { ScanIntensity, ScanTargetOptions } from '@/lib/api/scan-types'
import type { Translate } from './translate'
import type { ScanReadiness } from '../components/target-picker/selection-summary'
import { intensityTier, workflowTier, type ProbeTier } from './scan-intensity'

/**
 * The reason Next is disabled on the Targets step, or null when it may go on.
 * Only a selection where every target is blocked stops it: with some ready,
 * the Review step lists what will be skipped. An answer still on its way
 * (unknown) never blocks.
 */
export function targetsNextBlock(readiness: ScanReadiness, t: Translate): string | null {
  if (readiness.state !== 'blocked') return null
  const blocked = readiness.refused + readiness.unresolved.length
  if (readiness.refused === 0 && readiness.unresolved.length > 0) {
    return blocked === 1
      ? t('scans.targetsStep.nextBlockedUnresolvedOne')
      : t('scans.targetsStep.nextBlockedUnresolvedMany', undefined, { count: blocked })
  }
  return blocked === 1
    ? t('scans.targetsStep.nextBlockedOne')
    : t('scans.targetsStep.nextBlockedMany', undefined, { count: blocked })
}

/**
 * Whether the Targets step may offer "Lower intensity to <tier>": only for a
 * workflow (a single scanner probes at its own tier), below the current
 * intensity, and only when the chosen workflow still fits that tier (a lower
 * intensity would otherwise drop the workflow).
 */
export function lowerIntensityAllowed(
  form: { mode: string; intensity?: ScanIntensity },
  workflowSteps: Parameters<typeof workflowTier>[0] | null | undefined,
  tier: ProbeTier
): boolean {
  if (form.mode !== 'workflow' || !workflowSteps) return false
  if (tier >= intensityTier(form.intensity)) return false
  return workflowTier(workflowSteps) <= tier
}

/**
 * The one-line summary of the options of what a run resolves again (the
 * wildcards, inventory ranges): the freshness window, stale assets, and
 * whether names that do not resolve are kept. Comma separated, never a
 * middle dot. Ranges and coverage are not here: their choice is shown next
 * to their group.
 */
export function selectorOptionsSummary(
  t: Translate,
  options: ScanTargetOptions | undefined
): string {
  const parts: string[] = [
    options?.seen_within_days
      ? t('scans.targetOptions.seenWithin', undefined, { days: options.seen_within_days })
      : t('scans.dynamic.anyTimeSummary'),
  ]
  if (options?.include_stale) parts.push(t('scans.targetOptions.includesStale'))
  parts.push(
    options?.include_unresolved
      ? t('scans.targetsStep.unresolvedOn')
      : t('scans.targetsStep.unresolvedOff')
  )
  const line = parts
    .map((p, i) => (i === 0 ? p : p.charAt(0).toLocaleLowerCase() + p.slice(1)))
    .join(', ')
  return line.charAt(0).toLocaleUpperCase() + line.slice(1)
}
