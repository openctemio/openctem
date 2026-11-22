'use client'

/**
 * The scan page's headline facts, above the tabs: the last run, the next
 * run, how many runs and how many of them succeeded. Every figure comes from
 * the scan (its run counters and next run) or from its newest runs; a
 * figure the server does not give is not shown (no "findings reported"
 * count: that list opens from the Runs tab). Each run count opens the Runs
 * list of this scan with the matching status filter.
 *
 * `ScanActiveRun` says a run is in progress and offers Open and Cancel run.
 */

import { Fragment } from 'react'
import { RefreshCw, XCircle } from 'lucide-react'

import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import {
  DetailCallout,
  DetailStat,
  DetailStatGrid,
} from '@/features/shared/components/detail-sheet'
import { SCHEDULE_TYPE_LABELS, type ScanConfig, type ScanRun } from '@/lib/api/scan-types'
import { Can, Permission } from '@/lib/permissions'
import { safeHref } from '@/lib/safe-href'
import { BlockedRunHint } from '../last-run-cell'
import { ScheduleMissedNote } from '../schedule-missed-note'
import { formatScanDate } from '../../lib/format'
import { runTaskProgress } from '../../lib/run-display'
import { MIN_RUNS_FOR_RATE } from '../../lib/run-history'
import { isManagedScan, lastRunOf } from '../../lib/scan-status'

type RunCounts = {
  total: number
  inProgress: number
  successful: number
  partial: number
  failed: number
  successRate: number | null
}

const STATE_TONE: Record<string, 'destructive' | 'warning' | undefined> = {
  failed: 'destructive',
  partial: 'warning',
  timeout: 'warning',
  blocked: 'warning',
}

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

/** The Runs list of one scan, with a status filter when given. */
export function scanRunsHref(scanId: string, status?: string): string {
  const base = `/scans/runs?scan_id=${encodeURIComponent(scanId)}`
  return status ? `${base}&status=${status}` : base
}

const linkClass = 'underline-offset-2 hover:text-foreground hover:underline'

export function ScanFacts({
  config,
  counts,
  onViewRun,
  onChanged,
}: {
  config: ScanConfig
  counts: RunCounts | null
  onViewRun: (runId: string) => void
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const managed = isManagedScan(config)
  const last = lastRunOf(config)
  const lastKey = last ? (last.status === 'cancelled' ? 'canceled' : last.status) : null
  const total = counts?.total ?? config.total_runs
  const rate = counts?.successRate ?? null

  const nextNote =
    !managed && config.status === 'paused' && config.next_run_at
      ? t('scanDetail.metric.ifResumed')
      : !managed && config.schedule_type === 'manual'
        ? t('scanDetail.metric.manualOnly')
        : null
  const schedule = managed
    ? null
    : t(`scans.scheduleType.${config.schedule_type}`, SCHEDULE_TYPE_LABELS[config.schedule_type])
  const nextCaption = [nextNote, schedule, config.schedule_timezone].filter(Boolean).join(', ')

  const parts = [
    { key: 'ok', status: 'completed', n: config.successful_runs, word: 'successful' },
    { key: 'partial', status: 'partial', n: config.partial_runs ?? 0, word: 'partial' },
    { key: 'failed', status: 'failed', n: config.failed_runs, word: 'failed' },
  ] as const

  return (
    <section aria-label={t('scanDetail.fact.label', 'Scan facts')} data-slot="scan-facts">
      <DetailStatGrid>
        <DetailStat
          label={t('scanDetail.details.lastRun')}
          tone={lastKey ? STATE_TONE[lastKey] : undefined}
          value={
            last ? (
              <button
                type="button"
                className="truncate text-start hover:underline"
                onClick={() => onViewRun(last.id)}
              >
                {t(`scans.runStatus.${lastKey}`, capitalize(lastKey ?? ''))}
              </button>
            ) : (
              t('scanDetail.details.never')
            )
          }
          wrapCaption
          caption={
            last ? (
              <>
                {formatScanDate(last.started_at || last.created_at)}
                <BlockedRunHint run={last} className="mt-0.5 text-xs" />
              </>
            ) : undefined
          }
        />
        <DetailStat
          label={t('scanDetail.metric.nextRun')}
          value={
            config.next_run_at
              ? formatScanDate(config.next_run_at)
              : t('scanDetail.fact.notScheduled', 'Not scheduled')
          }
          wrapCaption
          caption={
            <>
              {nextCaption}
              <ScheduleMissedNote config={config} onViewRun={onViewRun} onChanged={onChanged} />
            </>
          }
        />
        <DetailStat
          label={t('scanDetail.metric.runs')}
          value={
            <Link href={safeHref(scanRunsHref(config.id)) ?? '/scans/runs'} className={linkClass}>
              {total}
            </Link>
          }
          wrapCaption
          caption={
            <>
              {parts.map((p, i) => (
                <Fragment key={p.key}>
                  {i > 0 && ', '}
                  <Link
                    href={safeHref(scanRunsHref(config.id, p.status)) ?? '/scans/runs'}
                    className={linkClass}
                  >
                    {t(`scanDetail.fact.${p.word}`, `{count} ${p.word}`, { count: p.n })}
                  </Link>
                </Fragment>
              ))}
              {counts && counts.inProgress > 0 && (
                <>
                  {', '}
                  {t('scanDetail.metric.inProgress', '{count} in progress', {
                    count: counts.inProgress,
                  })}
                </>
              )}
            </>
          }
        />
        <DetailStat
          label={t('scans.list.successRate')}
          value={rate === null ? t('scans.list.notAvailable') : `${rate}%`}
          wrapCaption
          caption={
            rate === null
              ? t('scanDetail.fact.rateTooFew', 'Shown after {count} finished runs', {
                  count: MIN_RUNS_FOR_RATE,
                })
              : t('scanDetail.fact.rateNote', 'Partly done runs count as successful')
          }
        />
      </DetailStatGrid>
    </section>
  )
}

export function ScanActiveRun({
  run,
  stopping,
  onOpen,
  onCancel,
}: {
  run: ScanRun
  stopping: boolean
  onOpen: () => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const progress = runTaskProgress(run.task_summary)
  const when = formatScanDate(run.started_at || run.created_at)
  return (
    <DetailCallout
      tone="info"
      icon={RefreshCw}
      title={t('scanDetail.run.inProgress')}
      actions={
        <>
          <Button size="sm" variant="outline" onClick={onOpen}>
            {t('scanDetail.run.open', 'Open run')}
          </Button>
          {/* POST /scan-runs/{id}/cancel needs scans:write. */}
          <Can permission={Permission.ScansWrite}>
            <Button
              size="sm"
              variant="outline"
              disabled={stopping}
              onClick={onCancel}
              aria-label={t('scanDetail.cancel.aria', 'Cancel run started {when}', { when })}
            >
              <XCircle className="me-1.5 h-4 w-4" aria-hidden />
              {t('confirm.scan.cancelRun', 'Cancel run')}
            </Button>
          </Can>
        </>
      }
    >
      {progress
        ? t('scanDetail.run.startedWithTasks', 'Started {when}, {tasks}.', {
            when,
            tasks: progress.label,
          })
        : t('scanDetail.run.started', 'Started {when}.', { when })}
    </DetailCallout>
  )
}
