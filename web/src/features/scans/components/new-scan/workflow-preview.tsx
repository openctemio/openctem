'use client'

import { useEffect, useState } from 'react'
import useSWR from 'swr'
import { AlertCircle, CheckCircle2 } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { SCAN_WINDOW_NEVER_OPENS, WindowWaits } from '@/features/scan-windows'
import { post } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'
import type { components } from '@/lib/api/generated/api.types'

type S = components['schemas']
export type WorkflowPreview =
  S['github_com_openctemio_openctem_api_internal_app_scan.WorkflowPreview']
export type WorkflowPreviewRequest = S['internal_infra_http_handler.WorkflowPreviewRequest']

const STATUS_LABEL: Record<string, string> = {
  ready: 'ready',
  outdated: 'ready (outdated)',
  offline_only: 'sensors offline',
  no_sensor: 'no sensor',
  disabled: 'disabled',
}

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}

/**
 * What a workflow scan would do if it started now, per step and for its
 * targets: computed by the API with the trigger's code
 * (POST /scans/workflow-preview). A blocking verdict is one the trigger
 * would refuse with.
 */
export function WorkflowPreviewSection({ request }: { request: WorkflowPreviewRequest }) {
  const debounced = useDebounced(request, 400)
  const ready =
    !!debounced.scan_workflow_id &&
    ((debounced.targets?.length ?? 0) > 0 || (debounced.asset_group_ids?.length ?? 0) > 0)
  const { data, error, isLoading } = useSWR(
    ready ? ['workflow-preview', JSON.stringify(debounced)] : null,
    () => post<WorkflowPreview>(scanEndpoints.workflowPreview(), debounced),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )

  return (
    <section
      aria-labelledby="workflow-preview-heading"
      className="space-y-3 border-t px-4 py-4 sm:px-6"
      data-testid="workflow-preview"
    >
      <div>
        <h3 id="workflow-preview-heading" className="text-sm font-semibold">
          Preview
        </h3>
        <p className="text-xs text-muted-foreground">
          What each step would run if the scan starts now.
        </p>
      </div>
      {!ready ? (
        <p className="text-sm text-muted-foreground">Add targets to preview the workflow.</p>
      ) : error ? (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Could not preview the workflow</AlertTitle>
          <AlertDescription>
            {error instanceof Error ? error.message : 'Try again.'}
          </AlertDescription>
        </Alert>
      ) : isLoading || !data ? (
        <Skeleton className="h-24 w-full" />
      ) : (
        <WorkflowPreviewBody preview={data} />
      )}
    </section>
  )
}

export function WorkflowPreviewBody({ preview }: { preview: WorkflowPreview }) {
  const targets = preview.targets
  return (
    <div className="space-y-3">
      {preview.blocking ? (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>The scan would not start as it is</AlertTitle>
          <AlertDescription>Fix the problems below, or start it later.</AlertDescription>
        </Alert>
      ) : (
        <p className="flex items-center gap-1.5 text-sm text-success">
          <CheckCircle2 className="h-4 w-4" /> Every step can run.
        </p>
      )}
      {targets?.windows && (
        <WindowWaits
          waitingCount={targets.windows.waiting_count}
          waiting={targets.windows.waiting}
          nextOpenAt={targets.windows.next_open_at}
          neverCount={targets.windows.never_count}
          never={targets.windows.never}
        />
      )}
      <ol className="space-y-2">
        {(preview.nodes ?? []).map((n, i) => (
          <li key={n.step_key ?? i} className="rounded-md border p-2 text-sm">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="font-medium">
                {i + 1}. {n.name}
              </span>
              {n.capability && (
                <Badge variant="outline" className="px-1 py-0 font-mono text-[10px]">
                  {n.capability}
                </Badge>
              )}
              {n.tier && (
                <Badge variant="outline" className="px-1 py-0 text-[10px]">
                  {n.tier}
                </Badge>
              )}
              {n.tool && (
                <span className="text-xs text-muted-foreground">
                  {n.pinned ? 'runs' : 'picks'} {n.tool}
                </span>
              )}
              {n.availability?.status && (
                <Badge variant="secondary" className="ms-auto px-1 py-0 text-[10px]">
                  {STATUS_LABEL[n.availability.status] ?? n.availability.status}
                  {n.availability.sensors_total
                    ? ` · ${n.availability.sensors_online ?? 0}/${n.availability.sensors_total} online`
                    : ''}
                </Badge>
              )}
            </div>
            {(n.chunk_size ?? 0) > 0 && (n.max_parallel_sensors ?? 0) > 0 && (
              <p className="mt-1 text-xs text-muted-foreground" data-testid="preview-parallel">
                Cut into chunks of {n.chunk_size}; up to {n.max_parallel_sensors} sensor(s) work on
                it at once.
              </p>
            )}
            {n.blocking?.message && (
              <p className="mt-1 text-xs text-destructive break-words">{n.blocking.message}</p>
            )}
          </li>
        ))}
      </ol>
      {targets && (
        <p className="text-xs text-muted-foreground">
          {targets.resolved_targets ?? 0} target(s) resolved
          {targets.excluded_targets ? `, ${targets.excluded_targets} excluded by scope` : ''}
          {targets.uncovered_targets ? `, ${targets.uncovered_targets} not scanned` : ''}.
          {targets.error?.message && targets.error.code !== SCAN_WINDOW_NEVER_OPENS
            ? ` ${targets.error.message}`
            : ''}
        </p>
      )}
    </div>
  )
}
