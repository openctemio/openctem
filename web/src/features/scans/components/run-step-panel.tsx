'use client'

import useSWR from 'swr'
import { X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { get } from '@/lib/api/client'
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type { RunMapNode, RunStepOutputs, RunTask } from '@/lib/api/generated'
import { toDisplayText } from '@/lib/untrusted-text'
import { nodeBadgeLines, outputsByType, outputsDeltaLabel, stepTasks } from '../lib/run-map'
import { RunTasksTable } from './run-tasks-table'

const PREVIEW_LIMIT = 20

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
  const delta = outputsDeltaLabel(node)
  // A sample of what the step produced, new ones first; only once it
  // produced something (in the caller's scope).
  const produced = (node.outputs?.total ?? 0) > 0
  const { data: preview, error: previewError } = useSWR<RunStepOutputs>(
    produced && key ? scanRunEndpoints.stepOutputs(runId, key, PREVIEW_LIMIT) : null,
    (url: string) => get<RunStepOutputs>(url),
    { revalidateOnFocus: false }
  )
  const listed = preview?.outputs ?? []
  const more = (preview?.total ?? 0) - listed.length

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
        {delta ? (
          <p className="mt-1 text-xs text-muted-foreground">Compared with the last run: {delta}</p>
        ) : null}
        {previewError ? (
          <p className="mt-1 text-xs text-muted-foreground">The outputs could not be listed.</p>
        ) : listed.length > 0 ? (
          <ul aria-label="Outputs" className="mt-2 space-y-0.5 text-xs">
            {listed.map((o) => (
              <li key={o.asset_id} className="flex items-center gap-2">
                <span className="min-w-0 flex-1 truncate" title={toDisplayText(o.name)}>
                  {toDisplayText(o.name)}
                </span>
                <span className="text-muted-foreground">{(o.type ?? '').replace(/_/g, ' ')}</span>
                {o.new ? (
                  <Badge variant="secondary" className="px-1 py-0 text-[10px]">
                    New
                  </Badge>
                ) : null}
              </li>
            ))}
            {more > 0 ? <li className="text-muted-foreground">and {more} more</li> : null}
          </ul>
        ) : null}
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
