import type { PipelineRun } from '@/lib/api/scan-types'
import { scanSuccessRate } from './format'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const IN_PROGRESS = new Set(['pending', 'queued', 'running'])

/** A run that has not finished yet (and can still be cancelled). */
export function isRunInProgress(run: { status: string }): boolean {
  return IN_PROGRESS.has(run.status)
}

/**
 * Who started a run, for the Trigger column. `triggered_by` is free text: a
 * user id for a manual trigger, otherwise "system", a schedule or a webhook
 * name. A user id is shown as the user's name (the API sends it as
 * `triggered_by_name`), never as a raw id; an id the API could not name
 * (a deleted user) reads "Unknown user".
 */
export function runTriggeredByLabel(
  run: Pick<PipelineRun, 'triggered_by' | 'triggered_by_name'>
): string | null {
  if (run.triggered_by_name) return run.triggered_by_name
  if (!run.triggered_by) return null
  return UUID.test(run.triggered_by) ? 'Unknown user' : run.triggered_by
}

/**
 * The run counts on a scan's page. The scan's own counters (total, successful,
 * failed) are bumped when a run FINISHES, so a scan whose first run is still
 * going read "Total runs 0" above a run history showing that run. Total adds
 * the runs in progress; successful, partial and failed stay finished-only.
 * successRate is scanSuccessRate (null before any run settled), the same
 * number the scan list shows.
 */
export function scanRunCounts(
  config: {
    total_runs: number
    successful_runs: number
    failed_runs: number
    partial_runs?: number
  },
  recentRuns: { status: string }[]
): {
  total: number
  inProgress: number
  successful: number
  partial: number
  failed: number
  successRate: number | null
} {
  const inProgress = recentRuns.filter(isRunInProgress).length
  return {
    total: config.total_runs + inProgress,
    inProgress,
    successful: config.successful_runs,
    partial: config.partial_runs ?? 0,
    failed: config.failed_runs,
    successRate: scanSuccessRate(config),
  }
}
