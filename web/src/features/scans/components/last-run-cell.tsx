'use client'

import Link from '@/components/link'
import { RelativeTime, RunStatusBadge } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import type { ScanLastRun } from '@/lib/api/scan-types'
import { safeHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import { blockedRunHint, lastRunReason } from '../lib/scan-status'

/**
 * Why the latest run was blocked, visible (not only on hover, which a phone
 * has not got), with a link to where it is fixed. Nothing for other states.
 */
export function BlockedRunHint({
  run,
  className,
}: {
  run: Pick<ScanLastRun, 'status' | 'refusal_code'> | null
  className?: string
}) {
  const { t } = useTranslation()
  const hint = blockedRunHint(run, t)
  if (!hint) return null
  return (
    <p
      data-slot="blocked-run-hint"
      className={cn('min-w-0 break-words text-meta text-muted-foreground', className)}
    >
      {hint.text}
      {hint.fix && (
        <>
          {' '}
          <Link
            href={safeHref(hint.fix.href) ?? '#'}
            className="font-medium text-foreground underline underline-offset-2"
            onClick={(e) => e.stopPropagation()}
          >
            {hint.fix.label}
          </Link>
        </>
      )}
    </p>
  )
}

/**
 * A scan's latest run: its real state (Running 42%, Completed, Partial,
 * Failed, Blocked...) and when it started, or "Never". The one way a scan's
 * run state is shown in lists and headers; the state chip is the shared
 * RunStatusBadge. Clicking opens the run when `onOpen` is given.
 */
export function LastRunCell({
  run,
  onOpen,
  showHint = false,
}: {
  run: ScanLastRun | null
  onOpen?: (runId: string) => void
  /** Show why a blocked run was refused under it, with the fix link. */
  showHint?: boolean
}) {
  const { t } = useTranslation()
  if (!run) {
    return <span className="text-sm text-muted-foreground">{t('scans.cell.never')}</span>
  }
  const reason = lastRunReason(run, t)
  // A run whose every task still waits in the queue is waiting for a sensor,
  // not "running 0%".
  const ts = run.task_summary
  const waiting =
    (run.status === 'running' || run.status === 'pending') &&
    !!ts &&
    ts.total > 0 &&
    ts.queued === ts.total
  const body = (
    <span className="flex min-w-0 flex-col items-start gap-0.5">
      <RunStatusBadge
        status={waiting ? 'queued' : run.status}
        progress={waiting ? undefined : run.progress}
        label={waiting ? t('scans.cell.waitingForSensor') : undefined}
        title={reason}
      />
      <RelativeTime date={run.started_at ?? run.created_at} className="text-xs" />
    </span>
  )
  const hint = showHint ? <BlockedRunHint run={run} className="mt-1 max-w-[16rem]" /> : null
  if (!onOpen)
    return hint ? (
      <div className="min-w-0">
        {body}
        {hint}
      </div>
    ) : (
      body
    )
  const button = (
    <button
      type="button"
      className="rounded-sm text-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      onClick={(e) => {
        e.stopPropagation()
        onOpen(run.id)
      }}
      aria-label={t('scans.cell.openLatestRun', undefined, { status: run.status })}
    >
      {body}
    </button>
  )
  return hint ? (
    <div className="min-w-0">
      {button}
      {hint}
    </div>
  ) : (
    button
  )
}
