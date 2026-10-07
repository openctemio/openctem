'use client'

import dynamic from 'next/dynamic'
import useSWR from 'swr'
import { CircleAlert, Hash } from 'lucide-react'
import { toast } from 'sonner'

import { Skeleton } from '@/components/ui/skeleton'
import { RunDispatchPanel } from '@/features/scan-zones'
import {
  DetailCallout,
  DetailCopyId,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
  ErrorState,
  RunStatusBadge,
} from '@/features/shared'
import { get } from '@/lib/api/client'
import { pipelineRunEndpoints } from '@/lib/api/endpoints'
import type { PipelineRun } from '@/lib/api/scan-types'
import { copyToClipboard } from '@/lib/clipboard'
import { toDisplayText } from '@/lib/untrusted-text'
import { formatScanDuration } from '@/features/scans/lib/format'
import { elapsedMs, runRefreshInterval, runTaskProgress } from '@/features/scans/lib/run-display'
import { RunTasksTable } from './run-tasks-table'
import { RunStageLanes } from './run-stage-lanes'

// Lazy: the workflow overlay pulls in the graph library only when a
// workflow run is opened.
const RunGraph = dynamic(() => import('./run-graph').then((m) => m.RunGraph), {
  ssr: false,
  loading: () => <Skeleton className="h-80 w-full" />,
})

interface RunDetailSheetProps {
  runId: string | null
  onOpenChange: (open: boolean) => void
}

function formatTime(ts?: string) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

function durationOf(run: PipelineRun): string | null {
  const ms = elapsedMs(run)
  if (ms === undefined) return null
  const label = ms < 1000 ? '<1s' : formatScanDuration(ms)
  return run.completed_at ? label : `${label} so far`
}

/** The callout over a run's message: what its status means, in its tone. */
export function runOutcomeCallout(status: string): {
  tone: 'warning' | 'destructive' | 'info'
  title: string
} {
  switch (status) {
    case 'partial':
      return {
        tone: 'warning',
        title: 'Some work did not finish; the results that came back are kept',
      }
    case 'timeout':
      return { tone: 'destructive', title: 'Run timed out' }
    case 'canceled':
      return { tone: 'info', title: 'Run canceled' }
    case 'failed':
      return { tone: 'destructive', title: 'Run failed' }
    default:
      return { tone: 'info', title: 'Run message' }
  }
}

/**
 * One scan run: status, timing and what its trigger dispatched (resolved and
 * excluded targets, zone routing, targets not scanned and why).
 */
export function RunDetailSheet({ runId, onOpenChange }: RunDetailSheetProps) {
  const {
    data: run,
    error,
    isLoading,
    mutate,
  } = useSWR<PipelineRun>(
    runId ? pipelineRunEndpoints.get(runId) : null,
    (url: string) => get<PipelineRun>(url),
    {
      revalidateOnFocus: false,
      // Live while the run is: status, task counts and duration refresh every
      // 5 s until it settles, then polling stops (a finished run never moves).
      refreshInterval: runRefreshInterval,
    }
  )
  const duration = run ? durationOf(run) : null
  const progress = run ? runTaskProgress(run.task_summary) : null

  return (
    <DetailSheet
      open={!!runId}
      onOpenChange={onOpenChange}
      header={
        <DetailHeader
          title="Scan run"
          badges={run ? <RunStatusBadge status={run.status} /> : undefined}
          meta={[run?.started_at ? `started ${formatTime(run.started_at)}` : null, duration]}
          menu={
            runId
              ? [
                  {
                    label: 'Copy run ID',
                    icon: Hash,
                    onSelect: () => {
                      copyToClipboard(runId)
                      toast.success('Run ID copied')
                    },
                  },
                ]
              : []
          }
          onClose={() => onOpenChange(false)}
        />
      }
    >
      {error ? (
        <ErrorState title="run" error={error} onRetry={() => void mutate()} />
      ) : isLoading || !run ? (
        <div className="space-y-3">
          <Skeleton className="h-6 w-1/3" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : (
        <div className="space-y-5">
          {run.error_message && (
            <DetailCallout
              tone={runOutcomeCallout(run.status).tone}
              icon={CircleAlert}
              title={runOutcomeCallout(run.status).title}
            >
              {/* Sensor and tool output can shape this text: control and
                  direction characters are shown as escapes, never applied. */}
              <span dir="auto" className="break-words [unicode-bidi:isolate]">
                {toDisplayText(run.error_message)}
              </span>
            </DetailCallout>
          )}

          <DetailStatGrid aria-label="Key numbers">
            <DetailStat label="Findings" value={run.total_findings} />
            {progress && <DetailStat label="Tasks" value={progress.label} />}
            {duration && <DetailStat label="Duration" value={duration} />}
          </DetailStatGrid>

          <DetailSections>
            {(run.step_runs?.length ?? 0) > 1 && (
              <DetailSection title="Workflow">
                <RunGraph
                  runId={run.id}
                  pipelineId={run.pipeline_id}
                  stepRuns={run.step_runs ?? []}
                  refreshInterval={runRefreshInterval(run)}
                />
              </DetailSection>
            )}
            <DetailSection title="Stages">
              <RunStageLanes runId={run.id} refreshInterval={runRefreshInterval(run)} />
            </DetailSection>
            <DetailSection title="Tasks" count={run.task_summary?.total}>
              {run.tasks && run.tasks.length > 0 ? (
                <RunTasksTable
                  runId={run.id}
                  tasks={run.tasks}
                  total={run.task_summary?.total ?? run.tasks.length}
                  nextCursor={run.tasks_truncated ? run.tasks_next_cursor : undefined}
                />
              ) : (
                <p className="text-sm text-muted-foreground">
                  This run has not dispatched any task.
                </p>
              )}
            </DetailSection>
            <DetailSection title="Dispatch">
              {run.dispatch ? (
                <RunDispatchPanel dispatch={run.dispatch} />
              ) : (
                <p className="text-sm text-muted-foreground">
                  This run recorded no dispatch details (runs from before target routing).
                </p>
              )}
            </DetailSection>
            <DetailSection title="Timing">
              <DetailFieldGrid>
                {run.scheduled_for && (
                  <DetailField label="Scheduled for">{formatTime(run.scheduled_for)}</DetailField>
                )}
                <DetailField label="Started">{formatTime(run.started_at)}</DetailField>
                <DetailField label="Completed">{formatTime(run.completed_at)}</DetailField>
                {runId && (
                  <DetailField label="Run ID" full>
                    <DetailCopyId id={runId} label="Run ID" />
                  </DetailField>
                )}
              </DetailFieldGrid>
            </DetailSection>
          </DetailSections>
        </div>
      )}
    </DetailSheet>
  )
}
