'use client'

import { Fragment, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { enTranslate, type Translate } from '../lib/translate'
import useSWRInfinite from 'swr/infinite'
import { AlertTriangle, FileText, Info, Loader2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { RunStatusBadge, TruncatedText } from '@/features/shared'
import { get } from '@/lib/api/client'
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type { RunTask, RunTaskPage } from '@/lib/api/generated'
import { formatScanDuration } from '@/features/scans/lib/format'
import { elapsedMs } from '@/features/scans/lib/run-display'
import { RunTaskLogsDialog } from '@/features/scans/components/run-task-logs-dialog'
import { holdText } from '@/features/scan-windows'
import {
  hostWaitLine,
  TaskPlacementPanel,
  WhyWaitingButton,
} from '@/features/scans/components/task-placement'

/**
 * Who runs a task: "Platform scanning" (never a platform sensor's name), the
 * tenant sensor's name, or nobody yet.
 */
export function taskSensorLabel(
  task: Pick<RunTask, 'sensor_name' | 'platform' | 'status'>,
  t: Translate = enTranslate
): string {
  if (task.platform) return t('scans.tasks.platformScanning')
  if (task.sensor_name) return task.sensor_name
  return task.status === 'queued' ? t('scans.tasks.waitingForSensor') : '-'
}

/** A queued task that is not waiting for its scan window can say why it waits. */
function canExplain(task: Pick<RunTask, 'id' | 'status' | 'window_hold'>): boolean {
  return task.status === 'queued' && !task.window_hold && !!task.id
}

/** What the API writes into a command handed back by its sensor (RFC-030 §5.12). */
const RELEASED_PREFIX = 'released by sensor'

/**
 * The line under a task's status. A queued task that its sensor handed back
 * (busy host, politeness, draining) carries the sensor's reason in its
 * message: that is why it waits, not an error, so it reads as information.
 * A queued task that waits for its scan window says which window and when
 * it opens (window_hold, RFC-067). Any other message is the task's error.
 */
export function taskStatusNote(
  task: Pick<
    RunTask,
    'status' | 'error_message' | 'window_hold' | 'waiting_on_hosts' | 'host_wait'
  >,
  t: Translate = enTranslate,
  runId = ''
): { kind: 'waiting' | 'error'; text: string; full?: boolean } | null {
  if (task.status === 'queued' && task.window_hold) {
    return { kind: 'waiting', text: holdText(task.window_hold) }
  }
  // Another task of the organization is scanning its hosts (research/130):
  // how many, held by which task, and how many targets can start, shown
  // in full.
  if (task.status === 'queued' && task.waiting_on_hosts) {
    if (task.host_wait) {
      return { kind: 'waiting', text: hostWaitLine(task.host_wait, runId, t), full: true }
    }
    return { kind: 'waiting', text: t('scans.tasks.waitingForHosts') }
  }
  const msg = task.error_message?.trim()
  if (!msg) return null
  if (task.status === 'queued' && msg.toLowerCase().startsWith(RELEASED_PREFIX)) {
    const reason = msg
      .slice(RELEASED_PREFIX.length)
      .replace(/^[:\s]+/, '')
      .trim()
    if (reason === 'hosts_busy') {
      return { kind: 'waiting', text: t('scans.tasks.handedBackHostsBusy') }
    }
    return {
      kind: 'waiting',
      text: reason
        ? t('scans.tasks.handedBackWhy', undefined, { reason })
        : t('scans.tasks.handedBack'),
    }
  }
  return { kind: 'error', text: msg }
}

/** A duration for a progress line: "<1s" under a second. */
function shortDuration(ms: number): string {
  return ms < 1000 ? '<1s' : formatScanDuration(ms)
}

/**
 * A running task's progress line (research/122): finished targets as its
 * sensor reports them, how long since the last one, and its budget. A task
 * that finished no target for more than half its stall window reads as
 * stalling, with when the platform takes it back. Null for a task that is
 * not running or reports nothing.
 */
export function taskProgressNote(
  task: Pick<RunTask, 'status' | 'progress' | 'budget_seconds' | 'stall_seconds' | 'started_at'>,
  t: Translate = enTranslate,
  now: number = Date.now()
): { kind: 'progress' | 'stalling'; text: string } | null {
  if (task.status !== 'running') return null
  const parts: string[] = []
  const p = task.progress
  const done = p?.done ?? 0
  const total = p?.total ?? 0
  if (p && total > 0) {
    parts.push(t('scans.tasks.progressDone', undefined, { done, total }))
    const since = Date.parse(p.last_progress_at ?? task.started_at ?? '')
    const quietMs = Number.isFinite(since) ? Math.max(0, now - since) : undefined
    const stallMs = (task.stall_seconds ?? 0) * 1000
    if (quietMs !== undefined && stallMs > 0 && done < total && quietMs > stallMs / 2) {
      return {
        kind: 'stalling',
        text: t('scans.tasks.stalling', undefined, {
          quiet: shortDuration(quietMs),
          stall: formatScanDuration(stallMs),
        }),
      }
    }
    if (quietMs !== undefined) {
      parts.push(t('scans.tasks.lastTarget', undefined, { ago: shortDuration(quietMs) }))
    }
  }
  if (task.budget_seconds) {
    parts.push(
      t('scans.tasks.budget', undefined, { budget: formatScanDuration(task.budget_seconds * 1000) })
    )
  }
  return parts.length ? { kind: 'progress', text: parts.join(', ') } : null
}

/** Skip reasons that have a translated label. */
const SKIP_REASONS = new Set([
  'unresolvable',
  'wildcard_pattern',
  'denied_by_policy',
  'invalid_target',
])

/** Skipped targets named in the note before "and N more". */
const SKIPPED_NAMED = 3

/**
 * The note of a task that completed with targets its sensor's local policy
 * skipped (a name that does not resolve, a wildcard pattern, a target
 * outside the policy): "Completed with 2 targets skipped: api.example.com
 * (does not resolve), …". Null when nothing was skipped. The targets are
 * sensor-supplied text; TruncatedText shows them as plain text.
 */
export function taskSkippedNote(
  task: Pick<RunTask, 'skipped_targets' | 'skipped_targets_total'>,
  t: Translate = enTranslate
): string | null {
  const list = task.skipped_targets ?? []
  const total = Math.max(task.skipped_targets_total ?? 0, list.length)
  if (total <= 0) return null
  const named = list
    .slice(0, SKIPPED_NAMED)
    .map(
      (s) =>
        `${s.target ?? '?'} (${t(SKIP_REASONS.has(s.reason ?? '') ? `scans.tasks.skip.${s.reason}` : 'scans.tasks.skip.refused')})`
    )
  const more = total - named.length
  let text = t(total === 1 ? 'scans.tasks.skippedOne' : 'scans.tasks.skippedMany', undefined, {
    count: total,
  })
  if (named.length > 0) text += `: ${named.join(', ')}`
  if (named.length > 0 && more > 0) text += t('scans.tasks.andMore', undefined, { count: more })
  return text
}

/** Coverage-gap reasons that have a translated label. */
const GAP_REASONS = new Set(['breaker_open', 'rate_floor', 'blocked'])

/**
 * The note of a task that completed with hosts its sensor could not fully
 * cover (the host stopped answering, kept rate-limiting the scan, or blocked
 * it): "Completed with 2 hosts not fully covered: api.example.com (stopped
 * answering), …". Null without gaps. A host with a gap is not "no findings".
 * The hosts are sensor-supplied text; TruncatedText shows them as plain text.
 */
export function taskCoverageGapNote(
  task: Pick<RunTask, 'coverage_gaps' | 'coverage_gaps_total'>,
  t: Translate = enTranslate
): string | null {
  const list = task.coverage_gaps ?? []
  const total = Math.max(task.coverage_gaps_total ?? 0, list.length)
  if (total <= 0) return null
  const named = list
    .slice(0, SKIPPED_NAMED)
    .map(
      (g) =>
        `${g.host ?? '?'} (${t(GAP_REASONS.has(g.reason ?? '') ? `scans.tasks.gap.${g.reason}` : 'scans.tasks.gap.other')})`
    )
  const more = total - named.length
  let text = t(total === 1 ? 'scans.tasks.gapsOne' : 'scans.tasks.gapsMany', undefined, {
    count: total,
  })
  if (named.length > 0) text += `: ${named.join(', ')}`
  if (named.length > 0 && more > 0) text += t('scans.tasks.gapsAndMore', undefined, { count: more })
  return text
}

/** Tasks per "Load more" page. */
export const TASK_PAGE_SIZE = 100

/**
 * The tasks of one run (RFC-046: one dispatched command = one tool, a slice of
 * targets, one sensor attempt). Targets are counted, not listed. The run read
 * embeds the first tasks; when there are more, "Load more" pages through
 * GET /scan-runs/{id}/tasks with the cursor the run read returned.
 */
export function RunTasksTable({
  runId,
  tasks,
  total,
  nextCursor,
}: {
  runId: string
  tasks: RunTask[]
  total: number
  /** Continues after `tasks` (the run read's tasks_next_cursor); none when all are shown. */
  nextCursor?: string
}) {
  const { t } = useTranslation()
  // Nothing is fetched until the first "Load more".
  const [started, setStarted] = useState(false)
  // The task whose logs are open (one dialog for the table).
  const [logsOf, setLogsOf] = useState<RunTask | null>(null)
  // The queued tasks whose "why waiting" is open.
  const [whyOpen, setWhyOpen] = useState<Set<string>>(() => new Set())
  const toggleWhy = (id: string) =>
    setWhyOpen((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  const { data, size, setSize, isValidating, error } = useSWRInfinite<RunTaskPage>(
    (index, prev: RunTaskPage | null) => {
      if (!started || !nextCursor) return null
      const cursor = index === 0 ? nextCursor : prev?.next_cursor
      return cursor ? scanRunEndpoints.tasks(runId, cursor, TASK_PAGE_SIZE) : null
    },
    (url: string) => get<RunTaskPage>(url),
    { revalidateFirstPage: false, revalidateOnFocus: false }
  )
  const more = (data ?? []).flatMap((p) => p.data ?? [])
  const rows = [...tasks, ...more]
  const lastPage = data?.[data.length - 1]
  const hasMore = !!nextCursor && (!started || !lastPage || !!lastPage.next_cursor)
  const loading = started && isValidating && (data?.length ?? 0) < size
  const remaining = Math.max(0, total - rows.length)

  return (
    <div className="space-y-2">
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-sm">
          <caption className="sr-only">
            {t('scans.tasks.caption', undefined, { shown: rows.length, total })}
          </caption>
          <thead className="bg-muted/50 text-xs text-muted-foreground">
            <tr>
              <th scope="col" className="px-3 py-2 text-start font-medium">
                {t('scans.tasks.colStatus')}
              </th>
              <th scope="col" className="px-3 py-2 text-start font-medium">
                {t('scans.tasks.colTool')}
              </th>
              <th scope="col" className="px-3 py-2 text-start font-medium">
                {t('scans.tasks.colSensor')}
              </th>
              <th scope="col" className="px-3 py-2 text-end font-medium">
                {t('scans.tasks.colTargets')}
              </th>
              <th scope="col" className="px-3 py-2 text-end font-medium">
                {t('scans.tasks.colDuration')}
              </th>
              <th scope="col" className="px-3 py-2 text-end font-medium">
                <span className="sr-only">{t('scans.tasks.colLogs')}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((task, i) => {
              const ms = elapsedMs(task)
              const note = taskStatusNote(task, t, runId)
              const skipped = taskSkippedNote(task, t)
              const gaps = taskCoverageGapNote(task, t)
              const prog = taskProgressNote(task, t)
              return (
                <Fragment key={task.id ?? i}>
                  <tr className="border-t align-top">
                    <td className="px-3 py-2">
                      <RunStatusBadge status={task.status ?? ''} />
                      {note?.kind === 'waiting' && (
                        <div className="mt-1 flex max-w-[260px] items-start gap-1 text-xs text-muted-foreground">
                          <Info className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                          {note.full ? (
                            <span className="break-words">{note.text}</span>
                          ) : (
                            <TruncatedText value={note.text} label={t('scans.tasks.waiting')} />
                          )}
                        </div>
                      )}
                      {canExplain(task) && (
                        <WhyWaitingButton
                          open={whyOpen.has(task.id ?? '')}
                          onToggle={() => toggleWhy(task.id ?? '')}
                        />
                      )}
                      {note?.kind === 'error' && (
                        <TruncatedText
                          value={note.text}
                          label={t('scans.tasks.error')}
                          className="mt-1 max-w-[220px] text-xs text-muted-foreground"
                        />
                      )}
                      {skipped && (
                        <div className="mt-1 flex max-w-[260px] items-start gap-1 text-xs text-warning">
                          <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                          <TruncatedText value={skipped} label={t('scans.tasks.skippedTargets')} />
                        </div>
                      )}
                      {gaps && (
                        <div className="mt-1 flex max-w-[260px] items-start gap-1 text-xs text-warning">
                          <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                          <TruncatedText value={gaps} label={t('scans.tasks.coverageGaps')} />
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2">{task.tool || '-'}</td>
                    <td className="px-3 py-2 text-muted-foreground">{taskSensorLabel(task, t)}</td>
                    <td className="px-3 py-2 text-end tabular-nums">{task.targets ?? 0}</td>
                    <td className="px-3 py-2 text-end tabular-nums text-muted-foreground">
                      {ms === undefined ? '-' : ms < 1000 ? '<1s' : formatScanDuration(ms)}
                      {ms !== undefined && !task.completed_at && t('scans.tasks.soFar')}
                      {prog && (
                        <div
                          className={
                            prog.kind === 'stalling'
                              ? 'mt-1 text-xs text-warning'
                              : 'mt-1 text-xs text-muted-foreground'
                          }
                        >
                          {prog.text}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 text-end">
                      {task.id && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 gap-1 px-2 text-xs"
                          aria-label={t('scans.tasks.logsOf', undefined, {
                            tool: task.tool || t('scans.tasks.task'),
                          })}
                          onClick={() => setLogsOf(task)}
                        >
                          <FileText className="h-3.5 w-3.5" aria-hidden="true" />
                          {t('scans.tasks.colLogs')}
                        </Button>
                      )}
                    </td>
                  </tr>
                  {canExplain(task) && whyOpen.has(task.id ?? '') && (
                    <tr>
                      <td colSpan={6} className="px-3 pb-3">
                        {/* Phone width: the table scrolls sideways; the panel stays in view. */}
                        <div className="sticky left-0 max-w-[calc(100vw-4rem)] sm:max-w-none">
                          <TaskPlacementPanel runId={runId} taskId={task.id ?? ''} />
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
      {rows.length < total && (
        <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
          <span aria-live="polite">
            {t('scans.tasks.showing', undefined, { shown: rows.length, total })}
          </span>
          {hasMore && (
            <Button
              variant="outline"
              size="sm"
              disabled={loading}
              aria-busy={loading}
              onClick={() => {
                if (!started) setStarted(true)
                else void setSize(size + 1)
              }}
            >
              {loading && (
                <Loader2 className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none" />
              )}
              {t('scans.tasks.loadMore', undefined, { count: Math.min(TASK_PAGE_SIZE, remaining) })}
            </Button>
          )}
          {error && <span className="text-destructive">{t('scans.tasks.loadFailed')}</span>}
        </div>
      )}
      {logsOf?.id && (
        <RunTaskLogsDialog
          runId={runId}
          taskId={logsOf.id}
          tool={logsOf.tool}
          task={logsOf}
          open
          onOpenChange={(o) => {
            if (!o) setLogsOf(null)
          }}
        />
      )}
    </div>
  )
}
