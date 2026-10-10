import type { ScanRun } from '@/lib/api/scan-types'
import { scanSuccessRate } from './format'
import { enTranslate, type Translate } from './translate'

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
/** What started a run that no person started, in words. */
const TRIGGER_TYPES = new Set([
  'automation',
  'schedule',
  'api',
  'webhook',
  'asset_discovery',
  'system',
])

export function runTriggeredByLabel(
  run: Pick<ScanRun, 'triggered_by' | 'triggered_by_name' | 'trigger'>,
  t: Translate = enTranslate
): string | null {
  const trigger = run.trigger
  if (trigger) {
    if (trigger.type === 'user') return trigger.label || t('scans.trigger.unknownUser')
    if (TRIGGER_TYPES.has(trigger.type)) return t(`scans.trigger.${trigger.type}`)
  }
  if (run.triggered_by_name) return run.triggered_by_name
  if (!run.triggered_by) return null
  return UUID.test(run.triggered_by) ? t('scans.trigger.unknownUser') : run.triggered_by
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
export function runTaskProgress(
  summary?: TaskCounts | null,
  t: Translate = enTranslate
): {
  label: string
  details: { key: 'running' | 'queued' | 'failed' | 'canceled'; count: number }[]
} | null {
  if (!summary || !summary.total || summary.total <= 0) return null
  const details = (['running', 'queued', 'failed', 'canceled'] as const)
    .map((key) => ({ key, count: summary[key] ?? 0 }))
    .filter((d) => d.count > 0)
  return {
    label: t('scans.run.tasksProgress', undefined, {
      done: summary.completed ?? 0,
      total: summary.total,
    }),
    details,
  }
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

/**
 * How often a list of runs refreshes: `liveMs` while one of them is in
 * progress, the slow `idleMs` otherwise (it only has to notice a run that a
 * schedule or another person starts). A function of the data, for SWR's
 * `refreshInterval`.
 */
export function runListRefreshInterval(
  liveMs: number,
  idleMs: number,
  /** True while the live runs' run:{id} notices arrive: no fast polling then. */
  realtime = false
) {
  return (page?: { data?: Array<{ status: string }> } | null): number =>
    page?.data?.some(isRunInProgress) && !realtime ? liveMs : idleMs
}

/** The ids of the runs of a list that are in progress (their channels to watch). */
export function liveRunIds(runs: Array<{ id: string; status: string }> | undefined): string[] {
  return (runs ?? []).filter(isRunInProgress).map((r) => r.id)
}

/** A list idle for this long refreshes at most this often. */
export const IDLE_RUN_LIST_REFRESH_MS = 120_000

/** The run kinds a person filters by (system runs are housekeeping: hidden). */
export const RUN_KIND_FILTERS = [
  { value: 'all' },
  { value: 'scan' },
  { value: 'quick' },
  { value: 'retest' },
] as const

const RUN_KINDS = new Set(['scan', 'quick', 'retest', 'validation', 'test', 'connector', 'system'])

/** A run kind in words; a run from before kinds existed is a scan. */
export function runKindLabel(kind?: string | null, t: Translate = enTranslate): string {
  const k = kind || 'scan'
  return RUN_KINDS.has(k) ? t(`scans.runKind.${k}`) : t('scans.runKind.run')
}

/** The finding a run is about (a retest), when it names one. */
export function runSubjectFindingId(run: { subject?: Record<string, unknown> }): string | null {
  const id = run.subject?.finding_id
  return typeof id === 'string' && id !== '' ? id : null
}

/** The Runs page with one run open (a retest's "View run"). */
export function runHref(runId: string): string {
  return `/scans/runs?run=${encodeURIComponent(runId)}`
}
