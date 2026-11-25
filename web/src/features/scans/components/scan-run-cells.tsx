'use client'

/**
 * The parts of a scan run's row, shared by the runs table's cells and the
 * run's phone card (`ScanRunMobileCard`), so both read the same facts in the
 * same words.
 */

import type { ReactNode } from 'react'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { RunStatusBadge } from '@/features/shared'
import type { ScanRun } from '@/lib/api/scan-workflow-types'
import { cn } from '@/lib/utils'
import { findingDetailHref } from '@/features/findings/lib/finding-link'
import { formatScanDuration } from '@/features/scans/lib/format'
import { scanDetailHref } from '@/features/scans/lib/scan-link'
import {
  elapsedMs,
  runKindLabel,
  runSubjectFindingId,
  runTargetNote,
  runTaskProgress,
} from '@/features/scans/lib/run-display'
import { RunManagedBadge } from './run-managed-badge'

type Translate = ReturnType<typeof useTranslation>['t']

/**
 * The Scan cell, on one line: the scan's name as a link to the scan, or what
 * the run is when it belongs to no scan (a retest, with its finding), then
 * the mark of a platform-managed scan.
 */
export function RunScanCell({ run }: { run: ScanRun }) {
  const { t } = useTranslation()
  const findingId = runSubjectFindingId(run)
  if (run.kind && run.kind !== 'scan' && run.kind !== 'quick') {
    return (
      <div data-slot="run-scan-cell" className="flex min-w-0 items-center gap-2">
        <span className="min-w-16 truncate font-medium">{runKindLabel(run.kind, t)}</span>
        <span className="flex min-w-0 shrink overflow-hidden">
          <RunManagedBadge managedBy={run.managed_by} />
        </span>
        {findingId && (
          <Link
            href={findingDetailHref(findingId)}
            className="shrink-0 text-xs text-muted-foreground hover:underline"
            onClick={(e) => e.stopPropagation()}
          >
            {t('scans.runs.openFinding')}
          </Link>
        )}
      </div>
    )
  }
  if (!run.scan_id) {
    return <span className="text-muted-foreground">{t('scans.runs.scanRun')}</span>
  }
  // Named by the server (quick scans and every page included); a run whose
  // scan was deleted keeps its row.
  if (!run.scan_name) {
    return <span className="text-muted-foreground">{t('scans.runs.deletedScan')}</span>
  }
  return (
    <div data-slot="run-scan-cell" className="flex min-w-0 items-center gap-2">
      <Link
        href={scanDetailHref(run.scan_id)}
        dir="auto"
        title={run.scan_name}
        // The run's name: it may end in an ellipsis, its full text the title.
        data-cut-tooltip=""
        className="min-w-16 truncate rounded-sm font-medium [unicode-bidi:isolate] hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none focus-visible:ring-inset"
        onClick={(e) => e.stopPropagation()}
      >
        {run.scan_name}
      </Link>
      {/* The mark gives way before the name does. */}
      <span className="flex min-w-0 shrink overflow-hidden">
        <RunManagedBadge managedBy={run.managed_by} />
      </span>
    </div>
  )
}

/**
 * Why the run ended as it did, beside its state: what the targets held back,
 * then the run's message (why it failed or was refused). Null when there is
 * nothing to add.
 */
export function runStateReason(run: ScanRun, t: Translate): string | null {
  const parts = [runTargetNote(run, t), run.error_message].filter(Boolean)
  return parts.length > 0 ? parts.join('. ') : null
}

/**
 * The run's state, then its reason as one muted line cut to the room left
 * (whole in the hover text and in the run's sheet). The state word is one
 * chip that never wraps and never shrinks.
 */
export function RunStateLine({
  run,
  extra,
  className,
}: {
  run: ScanRun
  /** Shown between the state and the reason (the intensity, on a phone). */
  extra?: ReactNode
  className?: string
}) {
  const { t } = useTranslation()
  const reason = runStateReason(run, t)
  return (
    <div
      data-slot="run-state"
      className={cn('flex min-w-0 items-center gap-2', className)}
      title={reason ?? undefined}
    >
      <RunStatusBadge status={run.status} className="shrink-0" />
      {extra}
      {reason && (
        <span
          data-slot="run-status-more"
          className="min-w-0 flex-1 truncate text-xs text-muted-foreground"
        >
          {reason}
        </span>
      )}
    </div>
  )
}

/** Tasks done of all, with what is running, queued, failed or canceled; steps before any task. */
export function RunTasksText({ run, className }: { run: ScanRun; className?: string }) {
  const { t } = useTranslation()
  const progress = runTaskProgress(run.task_summary, t)
  if (!progress) {
    // No task summary (nothing dispatched yet, or an older API): steps.
    const steps = t('scans.runs.steps', undefined, {
      done: run.completed_steps,
      total: run.total_steps,
    })
    const failed =
      run.failed_steps > 0
        ? t('scans.runs.stepsFailed', undefined, { count: run.failed_steps })
        : ''
    return (
      <span
        className={cn('block truncate text-sm tabular-nums', className)}
        title={failed ? `${steps} ${failed}` : steps}
      >
        {steps}
        {failed && <span className="ms-1 text-destructive">{failed}</span>}
      </span>
    )
  }
  const details = progress.details.map((d) => `${d.count} ${t(`scans.taskState.${d.key}`)}`)
  return (
    <span
      className={cn('block truncate text-sm tabular-nums', className)}
      title={[progress.label, ...details].join(', ')}
    >
      <span>{progress.label}</span>
      {progress.details.map((d, i) => (
        <span key={d.key} className="text-xs text-muted-foreground">
          {', '}
          <span className={d.key === 'failed' ? 'text-destructive' : undefined}>{details[i]}</span>
        </span>
      ))}
    </span>
  )
}

/**
 * How long the run took ("done"), has taken so far ("live"), or "Not started"
 * for a pending run ("waiting"). Null before it started otherwise.
 */
export function runDurationText(
  run: ScanRun,
  t: Translate
): { text: string; state: 'done' | 'live' | 'waiting' } | null {
  const ms = elapsedMs(run)
  if (ms === undefined) {
    return run.status === 'pending' ? { text: t('scans.runs.notStarted'), state: 'waiting' } : null
  }
  const label = ms < 1000 ? '<1s' : formatScanDuration(ms)
  return run.completed_at
    ? { text: label, state: 'done' }
    : { text: t('scans.runs.soFar', undefined, { duration: label }), state: 'live' }
}
