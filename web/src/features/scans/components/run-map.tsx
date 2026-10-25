'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import useSWR, { useSWRConfig } from 'swr'
import { get } from '@/lib/api/client'
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type { RunMap as RunMapData, RunTask } from '@/lib/api/generated'
import { useChannel } from '@/hooks/use-websocket'
import { zeroOutputWarnings, type EgressCountedTask } from '../lib/run-map'
import { RunFlow } from './run-flow'
import { RunStepPanel } from './run-step-panel'

/**
 * The live run map: the run drawn on the workflow version it executes as
 * one flow (RunFlow), each step with its state, chunks, outputs,
 * findings and duration, each dependency labelled with what flowed along it
 * (GET /scan-runs/{id}/map). Clicking a step opens its panel: state, error,
 * outputs and its tasks.
 */
export function RunMap({
  runId,
  refreshInterval,
  tasks,
  tasksTruncated,
  runKind,
}: {
  runId: string
  refreshInterval?: number
  /** The run's tasks as the run read returned them (the panel's task list). */
  tasks?: RunTask[]
  tasksTruncated?: boolean
  /** The run's kind (retest runs produce a verdict, not assets). */
  runKind?: string
}) {
  const { t } = useTranslation()
  const [selected, setSelected] = useState<string | null>(null)
  // Live: the run's change notices (run:{id}, at most one a second) refresh
  // every cached read of this run (map, run, tasks, stages, timeline). The
  // notice carries no data; polling stays as the fallback.
  const { mutate } = useSWRConfig()
  const runPrefix = `/api/v1/scan-runs/${encodeURIComponent(runId)}`
  useChannel({
    channelType: 'run',
    channelId: runId,
    onData: () => {
      void mutate((key) => typeof key === 'string' && key.startsWith(runPrefix))
    },
  })
  const { data, error, isLoading } = useSWR<RunMapData>(
    scanRunEndpoints.map(runId),
    (url: string) => get<RunMapData>(url),
    { revalidateOnFocus: false, refreshInterval, keepPreviousData: true }
  )

  const selectedNode = data?.nodes?.find((n) => n.step_key === selected)
  const warnings = useMemo(
    () => zeroOutputWarnings(data, t, tasks as EgressCountedTask[] | undefined),
    [data, t, tasks]
  )
  // The opened step's panel comes into view (it is drawn under the map).
  const panelRef = useRef<HTMLDivElement | null>(null)
  useEffect(() => {
    if (selected) panelRef.current?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' })
  }, [selected])

  if (error) {
    return <p className="text-sm text-muted-foreground">{t('scans.map.loadFailed')}</p>
  }
  if (isLoading && !data) {
    return <p className="text-sm text-muted-foreground">{t('scans.map.loading')}</p>
  }
  return (
    <div className="space-y-2">
      {data?.scan_workflow_version ? (
        <p className="text-xs text-muted-foreground">
          {t('scans.map.workflowVersion', undefined, { version: data.scan_workflow_version })}
        </p>
      ) : null}
      {warnings.length > 0 ? (
        <ul
          role="status"
          aria-label={t('scans.map.noOutputSteps')}
          className="space-y-0.5 text-xs text-warning"
        >
          {warnings.map((w) => (
            <li key={w.key}>{w.text}</li>
          ))}
        </ul>
      ) : null}
      {data ? (
        <RunFlow
          map={data}
          tasks={tasks as EgressCountedTask[] | undefined}
          selected={selected}
          onSelect={(key) => setSelected((cur) => (cur === key ? null : key))}
        />
      ) : null}
      <div ref={panelRef}>
        {selectedNode ? (
          <RunStepPanel
            runId={runId}
            node={selectedNode}
            tasks={tasks}
            tasksTruncated={tasksTruncated}
            runKind={runKind}
            onClose={() => setSelected(null)}
          />
        ) : null}
      </div>
    </div>
  )
}
