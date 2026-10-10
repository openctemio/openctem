'use client'

import dynamic from 'next/dynamic'
import { useTranslation } from '@/context/i18n-provider'
import { enTranslate, type Translate } from '../lib/translate'
import Link from '@/components/link'
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
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type { ScanRun } from '@/lib/api/scan-types'
import { copyToClipboard } from '@/lib/clipboard'
import { toDisplayText } from '@/lib/untrusted-text'
import { formatScanDuration } from '@/features/scans/lib/format'
import {
  elapsedMs,
  runKindLabel,
  runRefreshInterval,
  runSubjectFindingId,
  runTaskProgress,
} from '@/features/scans/lib/run-display'
import { RunTasksTable } from './run-tasks-table'
import { RunStageLanes } from './run-stage-lanes'
import { RunTimeline } from './run-timeline'

// Lazy: the workflow overlay pulls in the graph library only when a
// workflow run is opened.
const RunMap = dynamic(() => import('./run-map').then((m) => m.RunMap), {
  ssr: false,
})

interface RunDetailSheetProps {
  runId: string | null
  onOpenChange: (open: boolean) => void
}

function formatTime(ts?: string) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

function durationOf(run: ScanRun, t: Translate): string | null {
  const ms = elapsedMs(run)
  if (ms === undefined) return null
  const label = ms < 1000 ? '<1s' : formatScanDuration(ms)
  return run.completed_at ? label : t('scans.runDetail.soFar', undefined, { duration: label })
}

/** The callout over a run's message: what its status means, in its tone. */
export function runOutcomeCallout(
  status: string,
  t: Translate = enTranslate
): {
  tone: 'warning' | 'destructive' | 'info'
  title: string
} {
  switch (status) {
    case 'partial':
      return {
        tone: 'warning',
        title: t('scans.runDetail.partial'),
      }
    case 'timeout':
      return { tone: 'destructive', title: t('scans.runDetail.timeout') }
    case 'canceled':
      return { tone: 'info', title: t('scans.runDetail.canceled') }
    case 'failed':
      return { tone: 'destructive', title: t('scans.runDetail.failed') }
    case 'blocked':
      return { tone: 'destructive', title: t('scans.runDetail.blocked') }
    default:
      return { tone: 'info', title: t('scans.runDetail.message') }
  }
}

/**
 * One scan run: status, timing and what its trigger dispatched (resolved and
 * excluded targets, zone routing, targets not scanned and why).
 */
export function RunDetailSheet({ runId, onOpenChange }: RunDetailSheetProps) {
  const { t } = useTranslation()
  const {
    data: run,
    error,
    isLoading,
    mutate,
  } = useSWR<ScanRun>(
    runId ? scanRunEndpoints.get(runId) : null,
    (url: string) => get<ScanRun>(url),
    {
      revalidateOnFocus: false,
      // Live while the run is: status, task counts and duration refresh every
      // 5 s until it settles, then polling stops (a finished run never moves).
      refreshInterval: runRefreshInterval,
    }
  )
  const duration = run ? durationOf(run, t) : null
  const progress = run ? runTaskProgress(run.task_summary, t) : null
  // A run that executes no scan workflow (a retest) has no stages or
  // dispatch plan; it is about a finding instead.
  const isScanRun = !run?.kind || run.kind === 'scan' || run.kind === 'quick'
  const findingId = run ? runSubjectFindingId(run) : null

  return (
    <DetailSheet
      open={!!runId}
      onOpenChange={onOpenChange}
      header={
        <DetailHeader
          title={
            run && !isScanRun
              ? t('scans.runDetail.kindRun', undefined, { kind: runKindLabel(run.kind, t) })
              : t('scans.runDetail.scanRun')
          }
          badges={run ? <RunStatusBadge status={run.status} /> : undefined}
          meta={[
            run?.started_at
              ? t('scans.runDetail.started', undefined, { time: formatTime(run.started_at) })
              : null,
            duration,
          ]}
          menu={
            runId
              ? [
                  {
                    label: t('scans.runDetail.copyId'),
                    icon: Hash,
                    onSelect: () => {
                      copyToClipboard(runId)
                      toast.success(t('scans.runDetail.idCopied'))
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
        <ErrorState
          title={t('scans.runDetail.runNoun')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : isLoading || !run ? (
        <div className="space-y-3">
          <Skeleton className="h-6 w-1/3" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : (
        <div className="space-y-5">
          {run.error_message && (
            <DetailCallout
              tone={runOutcomeCallout(run.status, t).tone}
              icon={CircleAlert}
              title={runOutcomeCallout(run.status, t).title}
            >
              {/* Sensor and tool output can shape this text: control and
                  direction characters are shown as escapes, never applied. */}
              <span dir="auto" className="break-words [unicode-bidi:isolate]">
                {toDisplayText(run.error_message)}
              </span>
              {run.refusal_code && (
                <span className="mt-1 block font-mono text-xs text-muted-foreground">
                  {toDisplayText(run.refusal_code)}
                </span>
              )}
            </DetailCallout>
          )}

          {findingId && (
            <p className="text-sm">
              <Link
                href={`/findings/${encodeURIComponent(findingId)}`}
                className="font-medium underline-offset-2 hover:underline"
              >
                {t('scans.runDetail.aboutFinding')}
              </Link>
            </p>
          )}

          <DetailStatGrid aria-label={t('scans.runDetail.keyNumbers')}>
            <DetailStat label={t('scans.runDetail.findings')} value={run.total_findings} />
            {progress && <DetailStat label={t('scans.runDetail.tasks')} value={progress.label} />}
            {duration && <DetailStat label={t('scans.runDetail.duration')} value={duration} />}
          </DetailStatGrid>

          <DetailSections>
            {(run.scan_run_steps?.length ?? 0) > 0 && (
              <DetailSection title={t('scans.runDetail.runMap')}>
                <RunMap
                  runId={run.id}
                  refreshInterval={runRefreshInterval(run)}
                  tasks={run.tasks}
                  tasksTruncated={run.tasks_truncated}
                />
              </DetailSection>
            )}
            {isScanRun && (
              <DetailSection title={t('scans.runDetail.stages')}>
                <RunStageLanes runId={run.id} refreshInterval={runRefreshInterval(run)} />
              </DetailSection>
            )}
            <DetailSection title={t('scans.runDetail.timeline')}>
              <RunTimeline runId={run.id} refreshInterval={runRefreshInterval(run)} />
            </DetailSection>
            <DetailSection title={t('scans.runDetail.tasks')} count={run.task_summary?.total}>
              {run.tasks && run.tasks.length > 0 ? (
                <RunTasksTable
                  runId={run.id}
                  tasks={run.tasks}
                  total={run.task_summary?.total ?? run.tasks.length}
                  nextCursor={run.tasks_truncated ? run.tasks_next_cursor : undefined}
                />
              ) : (
                <p className="text-sm text-muted-foreground">{t('scans.runDetail.noTasks')}</p>
              )}
            </DetailSection>
            {isScanRun && (
              <DetailSection title={t('scans.runDetail.dispatch')}>
                {run.dispatch ? (
                  <RunDispatchPanel dispatch={run.dispatch} />
                ) : (
                  <p className="text-sm text-muted-foreground">{t('scans.runDetail.noDispatch')}</p>
                )}
              </DetailSection>
            )}
            <DetailSection title={t('scans.runDetail.timing')}>
              <DetailFieldGrid>
                {run.scheduled_for && (
                  <DetailField label={t('scans.runDetail.scheduledFor')}>
                    {formatTime(run.scheduled_for)}
                  </DetailField>
                )}
                <DetailField label={t('scans.runDetail.startedLabel')}>
                  {formatTime(run.started_at)}
                </DetailField>
                <DetailField label={t('scans.runDetail.completed')}>
                  {formatTime(run.completed_at)}
                </DetailField>
                {runId && (
                  <DetailField label={t('scans.runDetail.runId')} full>
                    <DetailCopyId id={runId} label={t('scans.runDetail.runId')} />
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
