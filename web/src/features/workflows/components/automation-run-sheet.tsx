'use client'

import { useMemo, useState } from 'react'
import { Pause, Play, XCircle } from 'lucide-react'
import { toast } from 'sonner'

import { useTranslation } from '@/context/i18n-provider'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DetailHeader, DetailSheet, RunStatusBadge } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  cancelWorkflowRun,
  invalidateWorkflowRunsCache,
  resumeWorkflowRun,
  useWorkflowRun,
} from '@/lib/api/workflow-hooks'
import type { WorkflowRun } from '@/lib/api/workflow-types'
import { Permission, useHasPermission } from '@/lib/permissions'
import { formatDay } from '../lib/use-person-name'
import { DeliveriesList, StepTrace, traceRowsFromNodeRuns } from './automation-trace-panels'

/** Translated run status words; an unknown status shows as it is. */
export function useRunStatusLabel() {
  const { t } = useTranslation()
  return (status: string): string => {
    switch (status) {
      case 'pending':
        return t('automations.runStatus.pending', 'Pending')
      case 'running':
        return t('automations.runStatus.running', 'Running')
      case 'completed':
        return t('automations.runStatus.completed', 'Completed')
      case 'failed':
        return t('automations.runStatus.failed', 'Failed')
      case 'canceled':
        return t('automations.runStatus.canceled', 'Canceled')
      case 'paused':
        return t('automations.runStatus.paused', 'Paused')
      default:
        return status
    }
  }
}

/** The body of a run: paused notice, per-step trace and what it sent or would send. */
export function AutomationRunDetail({
  run,
  nodeName,
}: {
  run: WorkflowRun
  nodeName: (nodeKey: string) => string | undefined
}) {
  const { t } = useTranslation()
  const canPublish = useHasPermission(Permission.AutomationsPublish)
  const [busy, setBusy] = useState<null | 'resume' | 'cancel'>(null)
  const mode = run.mode ?? 'live'
  const rows = useMemo(() => traceRowsFromNodeRuns(run.node_runs, nodeName), [run, nodeName])
  const deliveries = run.deliveries ?? []

  const act = async (what: 'resume' | 'cancel') => {
    setBusy(what)
    try {
      if (what === 'resume') {
        await resumeWorkflowRun(run.id)
        toast.success(t('automations.run.resumed', 'The run continues.'))
      } else {
        await cancelWorkflowRun(run.id)
        toast.success(t('automations.run.canceled', 'The run was canceled.'))
      }
      await invalidateWorkflowRunsCache()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          what === 'resume'
            ? t('automations.run.resumeFailed', 'Could not continue the run')
            : t('automations.run.cancelFailed', 'Could not cancel the run')
        )
      )
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="space-y-4" data-testid="run-detail">
      {run.status === 'paused' && (
        <Alert data-testid="run-paused">
          <Pause className="h-4 w-4" />
          <AlertTitle>{t('automations.run.pausedTitle', 'Paused at the change cap')}</AlertTitle>
          <AlertDescription className="space-y-2">
            <p>
              {run.pause_reason === 'blast_radius'
                ? t(
                    'automations.run.pausedBlastRadius',
                    'This run reached the most changes one run may make. A person with publish rights decides whether it continues.'
                  )
                : t('automations.run.pausedOther', 'This run is paused.')}
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                onClick={() => act('resume')}
                disabled={!canPublish || busy !== null}
              >
                <Play className="h-4 w-4" />
                {t('automations.run.continue', 'Continue')}
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => act('cancel')}
                disabled={!canPublish || busy !== null}
              >
                <XCircle className="h-4 w-4" />
                {t('automations.run.cancel', 'Cancel run')}
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      )}
      {run.error_message && <p className="text-sm text-destructive">{run.error_message}</p>}
      <Tabs defaultValue="trace">
        <TabsList>
          <TabsTrigger value="trace">{t('automations.run.tabTrace', 'Trace')}</TabsTrigger>
          <TabsTrigger value="deliveries">
            {mode === 'simulate'
              ? t('automations.run.tabWouldSend', 'Would send {n}', { n: deliveries.length })
              : t('automations.run.tabSent', 'Sent {n}', { n: deliveries.length })}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="trace" className="mt-3">
          <StepTrace rows={rows} />
        </TabsContent>
        <TabsContent value="deliveries" className="mt-3 space-y-2">
          <DeliveriesList deliveries={deliveries} mode={mode} />
          <p className="text-xs text-muted-foreground">
            {t(
              'automations.deliveries.redacted',
              'Payloads are stored redacted to the fields the channel may receive.'
            )}
          </p>
        </TabsContent>
      </Tabs>
    </div>
  )
}

/** A run's detail in the shared sheet: status, mode, retention and the trace. */
export function AutomationRunSheet({
  runId,
  workflowName,
  nodeName,
  onClose,
}: {
  runId: string
  workflowName?: string
  nodeName: (nodeKey: string) => string | undefined
  onClose: () => void
}) {
  const { t, locale } = useTranslation()
  const statusLabel = useRunStatusLabel()
  const { data: run, isLoading } = useWorkflowRun(runId)
  const mode = run?.mode ?? 'live'
  return (
    <DetailSheet
      open
      onOpenChange={(o) => !o && onClose()}
      width="lg"
      header={
        <DetailHeader
          title={workflowName ?? t('automations.runs.fallbackName', 'Workflow run')}
          badges={
            run ? (
              <>
                <RunStatusBadge status={run.status} label={statusLabel(run.status)} />
                <Badge variant="outline" className="text-xs">
                  {mode === 'simulate'
                    ? t('automations.mode.simulate', 'Simulate')
                    : t('automations.mode.live', 'Live')}
                </Badge>
              </>
            ) : null
          }
          meta={[
            run?.retained_until
              ? t('automations.run.keptUntil', 'Kept until {date}', {
                  date: formatDay(run.retained_until, locale),
                })
              : null,
          ]}
          onClose={onClose}
        />
      }
    >
      {isLoading || !run ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      ) : (
        <AutomationRunDetail run={run} nodeName={nodeName} />
      )}
    </DetailSheet>
  )
}
