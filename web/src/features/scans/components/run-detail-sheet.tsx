'use client'

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

interface RunDetailSheetProps {
  runId: string | null
  onOpenChange: (open: boolean) => void
}

function formatTime(ts?: string) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

function durationOf(run: PipelineRun): string | null {
  if (!run.started_at || !run.completed_at) return null
  const s = Math.max(0, (Date.parse(run.completed_at) - Date.parse(run.started_at)) / 1000)
  if (!Number.isFinite(s)) return null
  const m = Math.floor(s / 60)
  return m > 0 ? `${m}m ${Math.round(s % 60)}s` : `${Math.round(s)}s`
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
    { revalidateOnFocus: false }
  )
  const duration = run ? durationOf(run) : null

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
            <DetailCallout tone="destructive" icon={CircleAlert} title="Run failed">
              {run.error_message}
            </DetailCallout>
          )}

          <DetailStatGrid aria-label="Key numbers">
            <DetailStat label="Findings" value={run.total_findings} />
            {duration && <DetailStat label="Duration" value={duration} />}
          </DetailStatGrid>

          <DetailSections>
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
