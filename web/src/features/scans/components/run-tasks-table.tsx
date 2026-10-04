'use client'

import { RunStatusBadge } from '@/features/shared'
import type { RunTask } from '@/lib/api/generated'
import { formatScanDuration } from '@/features/scans/lib/format'
import { elapsedMs } from '@/features/scans/lib/run-display'

/** Who runs a task: the tenant sensor's name, "Platform sensor", or nobody yet. */
export function taskSensorLabel(
  task: Pick<RunTask, 'sensor_name' | 'platform' | 'status'>
): string {
  if (task.sensor_name) return task.sensor_name
  if (task.platform) return 'Platform sensor'
  return task.status === 'queued' ? 'Waiting for a sensor' : '-'
}

/**
 * The tasks of one run (RFC-046: one dispatched command = one tool, a slice of
 * targets, one sensor attempt). Targets are counted, not listed.
 */
export function RunTasksTable({
  tasks,
  truncated,
  total,
}: {
  tasks: RunTask[]
  truncated: boolean
  total: number
}) {
  return (
    <div className="space-y-2">
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-sm">
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
            </tr>
          </thead>
          <tbody>
            {tasks.map((t, i) => {
              const ms = elapsedMs(t)
              return (
                <tr key={t.id ?? i} className="border-t align-top">
                  <td className="px-3 py-2">
                    <RunStatusBadge status={t.status ?? ''} />
                    {t.error_message && (
                      <p
                        className="mt-1 max-w-[220px] truncate text-xs text-muted-foreground"
                        title={t.error_message}
                      >
                        {t.error_message}
                      </p>
                    )}
                  </td>
                  <td className="px-3 py-2">{t.tool || '-'}</td>
                  <td className="px-3 py-2 text-muted-foreground">{taskSensorLabel(t)}</td>
                  <td className="px-3 py-2 text-end tabular-nums">{t.targets ?? 0}</td>
                  <td className="px-3 py-2 text-end tabular-nums text-muted-foreground">
                    {ms === undefined ? '-' : ms < 1000 ? '<1s' : formatScanDuration(ms)}
                    {ms !== undefined && !t.completed_at && ' so far'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {truncated && (
        <p className="text-xs text-muted-foreground">
          Showing the first {tasks.length} of {total} tasks.
        </p>
      )}
    </div>
  )
}
