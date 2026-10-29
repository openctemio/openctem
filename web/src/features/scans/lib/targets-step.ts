/**
 * Whether the Targets step lets the wizard go on: Next is gated only when
 * nothing can run. Pure: the readiness is the server's scope check, read
 * through scanReadiness; nothing here decides scope.
 */

import type { ScanIntensity, ScanTargetOptions } from '@/lib/api/scan-types'
import type { Translate } from './translate'
import type { ScanReadiness } from '../components/target-picker/selection-summary'
import type { CoverageLevel } from './coverage-expansion'
import { describeTargetOptions, hasDynamicTargets } from './dynamic-targets'
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
 * The one-line summary of the Targets step's options disclosure: the coverage
 * level (when offered), how ranges and wildcards are resolved, and whether
 * names that do not resolve are kept. Joined by commas, never a middle dot.
 */
export function targetOptionsSummary(
  t: Translate,
  opts: {
    coverage?: CoverageLevel
    targets: readonly string[]
    options: ScanTargetOptions | undefined
  }
): string {
  const parts: string[] = []
  if (opts.coverage) parts.push(t(`scans.coverage.${opts.coverage}.label`))
  parts.push(...describeTargetOptions(opts.targets, opts.options, t))
  if (hasDynamicTargets(opts.targets, opts.options)) {
    parts.push(
      opts.options?.include_unresolved
        ? t('scans.targetsStep.unresolvedOn')
        : t('scans.targetsStep.unresolvedOff')
    )
  }
  const line = parts.join(', ')
  return line.charAt(0).toLocaleUpperCase() + line.slice(1)
}
