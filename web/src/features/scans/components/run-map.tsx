'use client'

import { useMemo, useState } from 'react'
import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type { RunMap as RunMapData, RunTask } from '@/lib/api/generated'
import { WorkflowStagesView } from '@/features/scan-workflows/components/workflow-stages'
import { mapEdgeLabel, mapStatus, mapSteps, nodeBadgeLines } from '../lib/run-map'
import { RunStepPanel } from './run-step-panel'

/**
 * The live run map: the run drawn on the workflow version it executes, each
 * step coloured by its state with its chunks, outputs and findings, each
 * dependency labelled with what flowed along it (GET /scan-runs/{id}/map).
 * Stages and graph views come from the shared WorkflowStages component.
 * Clicking a step opens its panel: state, error, outputs and its tasks.
 */
export function RunMap({
  runId,
  refreshInterval,
  tasks,
  tasksTruncated,
}: {
  runId: string
  refreshInterval?: number
  /** The run's tasks as the run read returned them (the panel's task list). */
  tasks?: RunTask[]
  tasksTruncated?: boolean
}) {
  const [selected, setSelected] = useState<string | null>(null)
  const { data, error, isLoading } = useSWR<RunMapData>(
    scanRunEndpoints.map(runId),
    (url: string) => get<RunMapData>(url),
    { revalidateOnFocus: false, refreshInterval, keepPreviousData: true }
  )

  const steps = useMemo(() => mapSteps(data), [data])
  const status = useMemo(() => mapStatus(data), [data])
  const edgeLabel = useMemo(() => mapEdgeLabel(data), [data])
  const badge = useMemo(() => {
    const out: Record<string, React.ReactNode> = {}
    for (const n of data?.nodes ?? []) {
      out[n.step_key ?? ''] = (
        <span className="flex flex-col gap-0.5 text-xs text-muted-foreground">
          {nodeBadgeLines(n).map((line) => (
            <span key={line}>{line}</span>
          ))}
        </span>
      )
    }
    return out
  }, [data])

  const selectedNode = data?.nodes?.find((n) => n.step_key === selected)

  if (error) {
    return <p className="text-sm text-muted-foreground">The run map could not be loaded.</p>
  }
  if (isLoading && !data) {
    return <p className="text-sm text-muted-foreground">Loading the run map…</p>
  }
  return (
    <div className="space-y-2">
      {data?.scan_workflow_version ? (
        <p className="text-xs text-muted-foreground">
          Workflow version {data.scan_workflow_version}, as the run started
        </p>
      ) : null}
      <WorkflowStagesView
        steps={steps}
        status={status}
        badge={badge}
        edgeLabel={edgeLabel}
        onSelectStep={(key) => setSelected((cur) => (cur === key ? null : key))}
      />
      {selectedNode ? (
        <RunStepPanel
          runId={runId}
          node={selectedNode}
          tasks={tasks}
          tasksTruncated={tasksTruncated}
          onClose={() => setSelected(null)}
        />
      ) : null}
    </div>
  )
}
