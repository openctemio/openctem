'use client'

import { useState } from 'react'
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

/**
 * Who runs a task: "Platform scanning" (never a platform sensor's name), the
 * tenant sensor's name, or nobody yet.
 */
export function taskSensorLabel(
  task: Pick<RunTask, 'sensor_name' | 'platform' | 'status'>
): string {
  if (task.platform) return 'Platform scanning'
  if (task.sensor_name) return task.sensor_name
  return task.status === 'queued' ? 'Waiting for a sensor' : '-'
}

/** What the API writes into a command handed back by its sensor (RFC-030 §5.12). */
const RELEASED_PREFIX = 'released by sensor'

/**
 * The line under a task's status. A queued task that its sensor handed back
 * (busy host, politeness, draining) carries the sensor's reason in its
 * message: that is why it waits, not an error, so it reads as information.
 * Any other message is the task's error.
 */
export function taskStatusNote(
  task: Pick<RunTask, 'status' | 'error_message'>
): { kind: 'waiting' | 'error'; text: string } | null {
  const msg = task.error_message?.trim()
  if (!msg) return null
  if (task.status === 'queued' && msg.toLowerCase().startsWith(RELEASED_PREFIX)) {
    const reason = msg
      .slice(RELEASED_PREFIX.length)
      .replace(/^[:\s]+/, '')
      .trim()
    return {
      kind: 'waiting',
      text: reason ? `Handed back: ${reason}` : 'Handed back by its sensor',
    }
  }
  return { kind: 'error', text: msg }
}

/** How a skipped target's reason reads. */
const SKIP_REASON_LABELS: Record<string, string> = {
  unresolvable: 'does not resolve',
  wildcard_pattern: 'wildcard pattern',
  denied_by_policy: "outside the sensor's policy",
  invalid_target: 'not a valid target',
}

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
  task: Pick<RunTask, 'skipped_targets' | 'skipped_targets_total'>
): string | null {
  const list = task.skipped_targets ?? []
  const total = Math.max(task.skipped_targets_total ?? 0, list.length)
  if (total <= 0) return null
  const named = list
    .slice(0, SKIPPED_NAMED)
    .map((s) => `${s.target ?? '?'} (${SKIP_REASON_LABELS[s.reason ?? ''] ?? 'refused'})`)
  const more = total - named.length
  let text = `Completed with ${total} target${total === 1 ? '' : 's'} skipped`
  if (named.length > 0) text += `: ${named.join(', ')}`
  if (named.length > 0 && more > 0) text += `, and ${more} more`
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
  // Nothing is fetched until the first "Load more".
  const [started, setStarted] = useState(false)
  // The task whose logs are open (one dialog for the table).
  const [logsOf, setLogsOf] = useState<RunTask | null>(null)
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
            Tasks of this run: {rows.length} of {total} shown
          </caption>
          <thead className="bg-muted/50 text-xs text-muted-foreground">
            <tr>
              <th scope="col" className="px-3 py-2 text-start font-medium">
                Status
              </th>
              <th scope="col" className="px-3 py-2 text-start font-medium">
                Tool
              </th>
              <th scope="col" className="px-3 py-2 text-start font-medium">
                Sensor
              </th>
              <th scope="col" className="px-3 py-2 text-end font-medium">
                Targets
              </th>
              <th scope="col" className="px-3 py-2 text-end font-medium">
                Duration
              </th>
              <th scope="col" className="px-3 py-2 text-end font-medium">
                <span className="sr-only">Logs</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((t, i) => {
              const ms = elapsedMs(t)
              const note = taskStatusNote(t)
              const skipped = taskSkippedNote(t)
              return (
                <tr key={t.id ?? i} className="border-t align-top">
                  <td className="px-3 py-2">
                    <RunStatusBadge status={t.status ?? ''} />
                    {note?.kind === 'waiting' && (
                      <div className="mt-1 flex max-w-[260px] items-start gap-1 text-xs text-muted-foreground">
                        <Info className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                        <TruncatedText value={note.text} label="Waiting" />
                      </div>
                    )}
                    {note?.kind === 'error' && (
                      <TruncatedText
                        value={note.text}
                        label="Task error"
                        className="mt-1 max-w-[220px] text-xs text-muted-foreground"
                      />
                    )}
                    {skipped && (
                      <div className="mt-1 flex max-w-[260px] items-start gap-1 text-xs text-warning">
                        <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                        <TruncatedText value={skipped} label="Skipped targets" />
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2">{t.tool || '-'}</td>
                  <td className="px-3 py-2 text-muted-foreground">{taskSensorLabel(t)}</td>
                  <td className="px-3 py-2 text-end tabular-nums">{t.targets ?? 0}</td>
                  <td className="px-3 py-2 text-end tabular-nums text-muted-foreground">
                    {ms === undefined ? '-' : ms < 1000 ? '<1s' : formatScanDuration(ms)}
                    {ms !== undefined && !t.completed_at && ' so far'}
                  </td>
                  <td className="px-3 py-2 text-end">
                    {t.id && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 gap-1 px-2 text-xs"
                        aria-label={`Logs of the ${t.tool || 'task'} task`}
                        onClick={() => setLogsOf(t)}
                      >
                        <FileText className="h-3.5 w-3.5" aria-hidden="true" />
                        Logs
                      </Button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {rows.length < total && (
        <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
          <span aria-live="polite">
            Showing {rows.length} of {total} tasks.
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
              Load {Math.min(TASK_PAGE_SIZE, remaining)} more
            </Button>
          )}
          {error && <span className="text-destructive">Could not load more tasks.</span>}
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
