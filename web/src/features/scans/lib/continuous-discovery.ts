/**
 * Continuous discovery (RFC-071): two scans saved together.
 *
 * 1. Passive discovery of the root domains (the form's scan, passive).
 * 2. Probe new assets of `*.<root>` (active), with
 *    `target_options.new_since_last_run`: each run probes only the assets
 *    that came into scope since its previous successful run. Names still
 *    under review are never probed (the API's active gate refuses them).
 */

import type { CreateScanConfigRequest } from '@/lib/api/scan-types'
import type { ScanWorkflow } from '@/lib/api/scan-workflow-types'
import { isWildcardTarget, toWildcards } from './dynamic-targets'

export interface ContinuousDiscoveryPair {
  passive: ScanWorkflow
  probe: ScanWorkflow
}

/** The two starter workflows, when both are offered. */
export function continuousDiscoveryPair(
  starters: readonly ScanWorkflow[]
): ContinuousDiscoveryPair | null {
  const passive = starters.find((w) => (w.tags ?? []).includes('passive'))
  const probe = starters.find((w) => (w.tags ?? []).includes('continuous'))
  return passive && probe ? { passive, probe } : null
}

/**
 * The probing scan of a continuous-discovery pair, from the passive scan's
 * request: its domains as `*.<domain>` selectors, the same schedule and
 * routing, active, only assets new since the last run. Null when the passive
 * scan names no domain (nothing to select under).
 */
export function probeNewAssetsRequest(
  passive: CreateScanConfigRequest,
  probeWorkflowId: string,
  name: string
): CreateScanConfigRequest | null {
  const selectors = toWildcards(passive.targets ?? []).filter(isWildcardTarget)
  if (selectors.length === 0) return null
  return {
    ...passive,
    name,
    intensity: 'active',
    scan_type: 'workflow',
    scan_workflow_id: probeWorkflowId,
    scanner_name: undefined,
    scanner_config: undefined,
    asset_ids: undefined,
    asset_group_id: undefined,
    asset_group_ids: undefined,
    targets: selectors,
    target_options: { ...(passive.target_options ?? {}), new_since_last_run: true },
  }
}

/** What happened to the probing scan of a pair. */
export type ProbeOutcome =
  { kind: 'saved' } | { kind: 'waiting' } | { kind: 'failed'; error: string }

/**
 * The probing scan was saved: it waits when no sensor with its tools is
 * online yet (the workflow's readiness says so), and runs on its own then.
 */
export function savedProbeOutcome(readinessState: string | undefined): ProbeOutcome {
  return readinessState === 'waiting' ? { kind: 'waiting' } : { kind: 'saved' }
}

export interface ProbeNote {
  /** A failed probe turns the one toast into a warning, never a second red toast. */
  variant: 'success' | 'warning'
  description?: string
  /** Where to add or check sensors, when the probe waits for one. */
  sensorsHref?: string
}

/** The note that joins the discovery scan's single result toast. */
export function probeNote(
  outcome: ProbeOutcome | null,
  t: (key: string, fallback?: string, params?: Record<string, string | number>) => string
): ProbeNote {
  if (!outcome || outcome.kind === 'saved') return { variant: 'success' }
  if (outcome.kind === 'waiting') {
    return {
      variant: 'success',
      description: t('scans.new.continuousProbeWaiting'),
      sensorsHref: '/sensors',
    }
  }
  return {
    variant: 'warning',
    description: t('scans.new.continuousSecondFailed', undefined, { error: outcome.error }),
  }
}
