'use client'

import { X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import type { RunMapNode, RunTask } from '@/lib/api/generated'
import { nodeBadgeLines, outputsByType, stepTasks } from '../lib/run-map'
import { RunTasksTable } from './run-tasks-table'

/**
 * One step of the run map, opened by clicking it: its state and why, its
 * error, what it produced by asset type and its own tasks (with their logs).
 * Tasks come from the run read (its first page): when the run has more, a
 * note says this step's list may be partial.
 */
export function RunStepPanel({
  runId,
  node,
  tasks,
  tasksTruncated,
  onClose,
}: {
  runId: string
  node: RunMapNode
  tasks?: RunTask[]
  tasksTruncated?: boolean
  onClose: () => void
}) {
  const key = node.step_key ?? ''
  const mine = stepTasks(tasks, key)
  const outputs = outputsByType(node)
  const [state, ...counts] = nodeBadgeLines(node)

  return (
    <section
      aria-label={`Step ${node.name || key}`}
      className="space-y-3 rounded-md border bg-card p-3 text-sm"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h4 className="truncate font-medium">{node.name || key}</h4>
          {node.tool ? <p className="text-xs text-muted-foreground">{node.tool}</p> : null}
        </div>
        <Button variant="ghost" size="icon" aria-label="Close the step" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </div>

      <div className="space-y-1 text-xs text-muted-foreground">
        <p>{state}</p>
        {counts.map((line) => (
          <p key={line}>{line}</p>
        ))}
        {node.error_message ? (
          <p className="whitespace-pre-wrap text-destructive">{node.error_message}</p>
        ) : null}
      </div>

      <div>
        <h5 className="mb-1 text-xs font-medium uppercase text-muted-foreground">Outputs</h5>
        {outputs.length === 0 ? (
          <p className="text-xs text-muted-foreground">Nothing produced yet.</p>
        ) : (
          <ul className="grid grid-cols-2 gap-x-4 text-xs">
            {outputs.map(([type, count]) => (
              <li key={type} className="flex justify-between">
                <span>{type.replace(/_/g, ' ')}</span>
                <span className="tabular-nums">{count}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h5 className="mb-1 text-xs font-medium uppercase text-muted-foreground">Tasks</h5>
        {mine.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            {tasksTruncated ? 'Not among the run tasks loaded so far.' : 'No task yet.'}
          </p>
        ) : (
          <>
            <RunTasksTable runId={runId} tasks={mine} total={mine.length} />
            {tasksTruncated ? (
              <p className="mt-1 text-xs text-muted-foreground">
                The run has more tasks than loaded: this step may have more.
              </p>
            ) : null}
          </>
        )}
      </div>
    </section>
  )
}
