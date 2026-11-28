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
  inline = false,
}: {
  run: ScanLastRun | null
  onOpen?: (runId: string) => void
  /** Show why a blocked run was refused under it, with the fix link. */
  showHint?: boolean
  /**
   * One line (a table row): the state, when it started and, for a blocked
   * run, the link to where it is fixed, side by side. The reason is the
   * state's hover text and the link's title.
   */
  inline?: boolean
}) {
  const { t, locale } = useTranslation()
  if (!run) {
    return <span className="text-sm text-muted-foreground">{t('scans.cell.never')}</span>
  }
  const reason = lastRunReason(run, t, locale)
  // A run whose every task still waits in the queue is waiting for a sensor,
  // not "running 0%".
  const ts = run.task_summary
  const waiting =
    (run.status === 'running' || run.status === 'pending') &&
    !!ts &&
    ts.total > 0 &&
    ts.queued === ts.total
  const body = (
    <span
      className={cn(
        'flex min-w-0',
        inline
          ? 'items-center gap-2 whitespace-nowrap [&>:first-child]:shrink-0'
          : 'flex-col items-start gap-0.5'
      )}
    >
      <RunStatusBadge
        status={waiting ? 'queued' : run.status}
        progress={waiting ? undefined : run.progress}
        label={waiting ? t('scans.cell.waitingForSensor') : undefined}
        title={reason}
      />
      <RelativeTime
        date={run.started_at ?? run.created_at}
        // In a row the time wraps between its words, never cut.
        className={cn('text-xs', inline && 'min-w-0 whitespace-normal')}
      />
    </span>
  )
  if (inline) {
    const blocked = showHint ? blockedRunHint(run, t) : null
    return (
      // The fix link drops under the state and time when they do not fit
      // beside it, so a wrapped time never runs under the link.
      <div
        data-slot="last-run-cell"
        className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5"
      >
        {onOpen ? (
          <button
            type="button"
            className="flex min-w-0 rounded-sm text-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            onClick={(e) => {
              e.stopPropagation()
              onOpen(run.id)
            }}
            aria-label={t('scans.cell.openLatestRun', undefined, { status: run.status })}
          >
            {body}
          </button>
        ) : (
          <span className="flex min-w-0">{body}</span>
        )}
        {blocked?.fix && (
          <Link
            href={safeHref(blocked.fix.href) ?? '#'}
            title={blocked.text}
            className="shrink-0 text-meta font-medium text-foreground underline underline-offset-2"
            onClick={(e) => e.stopPropagation()}
          >
            {blocked.fix.label}
          </Link>
        )}
      </div>
    )
  }
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
