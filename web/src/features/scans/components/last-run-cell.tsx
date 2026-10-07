'use client'

import { RelativeTime, RunStatusBadge } from '@/features/shared'
import type { ScanLastRun } from '@/lib/api/scan-types'
import { lastRunReason } from '../lib/scan-status'

/**
 * A scan's latest run: its real state (Running 42%, Completed, Partial,
 * Failed, Blocked...) and when it started, or "Never". The one way a scan's
 * run state is shown in lists and headers; the state chip is the shared
 * RunStatusBadge. Clicking opens the run when `onOpen` is given.
 */
export function LastRunCell({
  run,
  onOpen,
}: {
  run: ScanLastRun | null
  onOpen?: (runId: string) => void
}) {
  if (!run) {
    return <span className="text-sm text-muted-foreground">Never</span>
  }
  const reason = lastRunReason(run)
  const body = (
    <span className="flex min-w-0 flex-col items-start gap-0.5">
      <RunStatusBadge status={run.status} progress={run.progress} title={reason} />
      <RelativeTime date={run.started_at ?? run.created_at} className="text-xs" />
    </span>
  )
  if (!onOpen) return body
  return (
    <button
      type="button"
      className="rounded-sm text-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      onClick={(e) => {
        e.stopPropagation()
        onOpen(run.id)
      }}
      aria-label={`Open the latest run (${run.status})`}
    >
      {body}
    </button>
  )
}
