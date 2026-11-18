'use client'

import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import useSWR from 'swr'
import { AlertCircle, AlertTriangle, CheckCircle2, SkipForward } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { SCAN_WINDOW_NEVER_OPENS, WindowWaits } from '@/features/scan-windows'
import { post } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'
import type { components } from '@/lib/api/generated/api.types'
import { ExcludedTargetsList } from '../excluded-targets-list'

type S = components['schemas']
export type WorkflowPreview =
  S['github_com_openctemio_openctem_api_internal_app_scan.WorkflowPreview']
export type WorkflowPreviewRequest = S['internal_infra_http_handler.WorkflowPreviewRequest']

const STATUS_KEYS: Record<string, string> = {
  ready: 'scans.wfPreview.ready',
  outdated: 'scans.wfPreview.outdated',
  offline_only: 'scans.wfPreview.offline_only',
  no_sensor: 'scans.wfPreview.no_sensor',
  disabled: 'scans.wfPreview.disabled',
}

/** Skip codes the API returns for a step the run will not start (RFC-054 skip codes). */
const SKIP_KEYS: Record<string, string> = {
  DEPTH_SKIPPED: 'scans.wfPreview.skipped.DEPTH_SKIPPED',
  NO_MATCHING_TOOL: 'scans.wfPreview.skipped.NO_MATCHING_TOOL',
  TOOL_NOT_INSTALLED: 'scans.wfPreview.skipped.NO_MATCHING_TOOL',
  TOOL_DISABLED: 'scans.wfPreview.skipped.TOOL_DISABLED',
  NO_SENSOR_FOR_TOOL: 'scans.wfPreview.skipped.NO_SENSOR_FOR_TOOL',
  DEPENDENCY_SKIPPED: 'scans.wfPreview.skipped.DEPENDENCY_SKIPPED',
}

/** The line shown under a skipped step: translated by code, the server text as fallback. */
export function skipText(
  t: (key: string, fallback?: string, vars?: Record<string, string | number>) => string,
  skipped: { code?: string; message?: string },
  capability?: string
): string {
  const key = skipped.code ? SKIP_KEYS[skipped.code] : undefined
  if (!key) return skipped.message ?? ''
  return t(key, skipped.message, { capability: capability ?? '' })
}

/**
 * Step refusals a run turns into skips, on a required step as on an optional
 * one (server step_support.go): no tool runs the capability, the pinned tool
 * is not installed or is turned off, or no sensor may run the tool. The
 * preview reports them on a required step as blocking; the run skips the
 * step and goes on with the others, so they show as skips and never stop a
 * scan from being created (a scan runs what is supported).
 */
const TOOL_SKIP_CODES: Record<string, string> = {
  NO_MATCHING_TOOL: 'NO_MATCHING_TOOL',
  TOOL_NOT_FOUND: 'TOOL_NOT_INSTALLED',
  TOOL_NOT_INSTALLED: 'TOOL_NOT_INSTALLED',
  TOOL_DISABLED: 'TOOL_DISABLED',
  NO_SENSOR_FOR_TOOL: 'NO_SENSOR_FOR_TOOL',
}

/** A workflow preview as the run would go: tool and sensor gaps are skips. */
export interface RunPreview extends WorkflowPreview {
  /** Steps skipped for a missing tool or sensor, required ones included. */
  toolSkips: number
  /** No step can run: a start is refused until a tool or sensor is there. */
  noStepRuns: boolean
}

export function asRunPreview(preview: WorkflowPreview | RunPreview): RunPreview {
  if ('toolSkips' in preview) return preview
  let toolSkips = 0
  const nodes = (preview.nodes ?? []).map((n) => {
    const code = n.blocking?.code ? TOOL_SKIP_CODES[n.blocking.code] : undefined
    if (!code) return n
    toolSkips++
    return { ...n, blocking: undefined, skipped: { code, message: n.blocking?.message } }
  })
  return {
    ...preview,
    nodes,
    blocking: !!preview.targets?.error || nodes.some((n) => !!n.blocking),
    toolSkips,
    noStepRuns: nodes.length > 0 && nodes.every((n) => !!n.skipped),
  }
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
export function useWorkflowPreview(request: WorkflowPreviewRequest, enabled = true) {
  const debounced = useDebounced(request, 400)
  const ready =
    enabled &&
    !!debounced.scan_workflow_id &&
    ((debounced.targets?.length ?? 0) > 0 || (debounced.asset_group_ids?.length ?? 0) > 0)
  const { data, error, isLoading } = useSWR(
    ready ? ['workflow-preview', JSON.stringify(debounced)] : null,
    () => post<WorkflowPreview>(scanEndpoints.workflowPreview(), debounced),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
  const run = useMemo(() => (data ? asRunPreview(data) : undefined), [data])
  return { data: run, error, isLoading, ready }
}

export function WorkflowPreviewSection({ request }: { request: WorkflowPreviewRequest }) {
  const { t } = useTranslation()
  const { data, error, isLoading, ready } = useWorkflowPreview(request)

  return (
    <section
      aria-labelledby="workflow-preview-heading"
      className="space-y-3 border-t px-4 py-4 sm:px-6"
      data-testid="workflow-preview"
    >
      <div>
        <h3 id="workflow-preview-heading" className="text-sm font-semibold">
          {t('scans.wfPreview.title')}
        </h3>
        <p className="text-xs text-muted-foreground">{t('scans.wfPreview.subtitle')}</p>
      </div>
      {!ready ? (
        <p className="text-sm text-muted-foreground">{t('scans.wfPreview.addTargets')}</p>
      ) : error ? (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>{t('scans.wfPreview.failed')}</AlertTitle>
          <AlertDescription>
            {error instanceof Error ? error.message : t('scans.wfPreview.tryAgain')}
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

export function WorkflowPreviewBody({ preview: raw }: { preview: WorkflowPreview }) {
  const { t } = useTranslation()
  const preview = asRunPreview(raw)
  const targets = preview.targets
  return (
    <div className="space-y-3">
      {preview.blocking ? (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>{t('scans.wfPreview.wouldNotStart')}</AlertTitle>
          <AlertDescription>{t('scans.wfPreview.fixProblems')}</AlertDescription>
        </Alert>
      ) : preview.noStepRuns ? (
        <p
          className="flex items-start gap-1.5 text-sm text-foreground"
          data-testid="preview-no-step-runs"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
          {t('scans.wfPreview.noStepRuns')}
        </p>
      ) : preview.toolSkips > 0 ? (
        <p
          className="flex items-start gap-1.5 text-sm text-foreground"
          data-testid="preview-runs-in-part"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
          {t('scans.wfPreview.runsInPart', undefined, { count: preview.toolSkips })}
        </p>
      ) : (
        <p className="flex items-center gap-1.5 text-sm text-success">
          <CheckCircle2 className="h-4 w-4" /> {t('scans.wfPreview.everyStep')}
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
                  {t(n.pinned ? 'scans.wfPreview.runs' : 'scans.wfPreview.picks', undefined, {
                    tool: n.tool,
                  })}
                </span>
              )}
              {n.availability?.status && (
                <Badge variant="secondary" className="ms-auto px-1 py-0 text-[10px]">
                  {STATUS_KEYS[n.availability.status]
                    ? t(STATUS_KEYS[n.availability.status])
                    : n.availability.status}
                  {n.availability.sensors_total
                    ? t('scans.wfPreview.online', undefined, {
                        online: n.availability.sensors_online ?? 0,
                        total: n.availability.sensors_total,
                      })
                    : ''}
                </Badge>
              )}
            </div>
            {(n.chunk_size ?? 0) > 0 && (n.max_parallel_sensors ?? 0) > 0 && (
              <p className="mt-1 text-xs text-muted-foreground" data-testid="preview-parallel">
                {t('scans.wfPreview.chunks', undefined, {
                  size: n.chunk_size ?? 0,
                  sensors: n.max_parallel_sensors ?? 0,
                })}
              </p>
            )}
            {n.skipped && (
              <p
                className="mt-1 flex items-start gap-1.5 text-xs text-warning break-words"
                data-testid="preview-skipped"
              >
                <SkipForward className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                <span className="min-w-0">{skipText(t, n.skipped, n.capability)}</span>
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
          {t('scans.wfPreview.resolved', undefined, { count: targets.resolved_targets ?? 0 })}
          {targets.excluded_targets
            ? t('scans.wfPreview.excluded', undefined, { count: targets.excluded_targets })
            : ''}
          {targets.uncovered_targets
            ? t('scans.wfPreview.uncovered', undefined, { count: targets.uncovered_targets })
            : ''}
          .
          {targets.error?.message && targets.error.code !== SCAN_WINDOW_NEVER_OPENS
            ? ` ${targets.error.message}`
            : ''}
        </p>
      )}
      {targets && (targets.excluded_detail?.length ?? 0) > 0 && (
        <ExcludedTargetsList
          items={targets.excluded_detail ?? []}
          total={targets.excluded_targets ?? 0}
        />
      )}
    </div>
  )
}
