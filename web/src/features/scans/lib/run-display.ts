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
 * The run counts on a scan's page. The scan's counters are recomputed from
 * its runs by the API, so total_runs already includes the runs in progress
 * (and blocked runs); inProgress is how many of the latest runs are still
 * going. successRate is scanSuccessRate (null before any run settled), the
 * same number the scan list shows.
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
    total: config.total_runs,
    inProgress,
    successful: config.successful_runs,
    partial: config.partial_runs ?? 0,
    failed: config.failed_runs,
    successRate: scanSuccessRate(config),
  }
}

/** Task counts as the runs page reads them (GET /scan-runs). */
export interface TaskCounts {
  total?: number
  queued?: number
  running?: number
  completed?: number
  failed?: number
  canceled?: number
}

/**
 * Progress of a run in tasks (RFC-046: a run is cut into tasks, one per
 * dispatched command): "3/5 tasks" with the counts still worth a glance.
 * Null when the API sent no task summary (a run that dispatched nothing, or
 * an API without it), so the caller can fall back to steps.
 */
export function runTaskProgress(summary?: TaskCounts | null): {
  label: string
  details: { key: 'running' | 'queued' | 'failed' | 'canceled'; count: number }[]
} | null {
  if (!summary || !summary.total || summary.total <= 0) return null
  const details = (['running', 'queued', 'failed', 'canceled'] as const)
    .map((key) => ({ key, count: summary[key] ?? 0 }))
    .filter((d) => d.count > 0)
  return { label: `${summary.completed ?? 0}/${summary.total} tasks`, details }
}

/**
 * Elapsed time of a run or task in ms: start to completion, or start to `now`
 * while it is still going. Undefined before it started or when the
 * timestamps make no sense (completion before start).
 */
export function elapsedMs(
  item: { started_at?: string | null; completed_at?: string | null },
  now: number = Date.now()
): number | undefined {
  if (!item.started_at) return undefined
  const start = Date.parse(item.started_at)
  const end = item.completed_at ? Date.parse(item.completed_at) : now
  const ms = end - start
  return Number.isFinite(ms) && ms >= 0 ? ms : undefined
}

/** How often an open run refreshes: every 5 s while it is live, never once settled. */
export const LIVE_RUN_REFRESH_MS = 5000

export function runRefreshInterval(run?: { status: string } | null): number {
  return run && isRunInProgress(run) ? LIVE_RUN_REFRESH_MS : 0
}
