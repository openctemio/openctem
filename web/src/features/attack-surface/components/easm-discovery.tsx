'use client'

/**
 * Attack surface > Discovery: the organization's coverage work in four
 * stages (asset discovery, exposure scan, validation and scoping, technology
 * discovery). Each stage shows its status, last run and progress and can be
 * run; Run all runs every stage and Abort all cancels the active coverage
 * runs. Run only makes the stage's pairs due: the coverage loop plans them on
 * its next pass through the dispatch gate, so scope, tiers and the daily
 * budget still decide every target. The API is the only authority.
 */

import { useCallback, useMemo, useState } from 'react'
import { Download, Info, Play, RefreshCw, ShieldX, Square } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  EmptyState,
  ErrorState,
  GatedButton,
  KeyValueList,
  Meter,
  MetricStrip,
  RelativeTime,
  TonePill,
  type MetricStripItem,
  type PillTone,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { downloadCsv } from '@/hooks/use-csv-export'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  abortAllDiscovery,
  runAllDiscovery,
  runDiscoveryStage,
  useEASMDiscovery,
} from '../hooks/use-easm-discovery'
import {
  anyRunning,
  discoveryCsv,
  runLimited,
  type DiscoveryStage,
  type DiscoveryStageRow,
  type DiscoveryStatus,
} from '../lib/discovery'

const STATUS_TONE: Record<DiscoveryStatus, PillTone> = {
  idle: 'muted',
  running: 'info',
  paused: 'warning',
  failed: 'destructive',
}

const STATUS_LABEL: Record<DiscoveryStatus, string> = {
  idle: 'Idle',
  running: 'Running',
  paused: 'Paused',
  failed: 'Failed',
}

const STAGE_LABEL: Record<DiscoveryStage, string> = {
  asset_discovery: 'Asset discovery',
  exposure_scan: 'Exposure scan',
  validation_scoping: 'Validation & scoping',
  technology_discovery: 'Technology discovery',
}

const STAGE_DESCRIPTION: Record<DiscoveryStage, string> = {
  asset_discovery:
    'Finds new names and hosts under your domains, from passive sources and active enumeration.',
  exposure_scan: 'Checks what the known surface exposes: open ports and template checks.',
  validation_scoping:
    'Resolves names and looks up registration and network ownership, the facts attribution and scope decisions read.',
  technology_discovery: 'Probes web services and records the technologies each one runs.',
}

const REASON_LABEL: Record<string, string> = {
  coverage_off: 'Automatic coverage is off',
  policy_disabled: 'A policy holds it',
  no_scope: 'No active scope entry',
  tool_missing: 'No sensor has the tool',
  tool_not_allowed: 'The tool is not allowed on your sensors',
  sensor_offline: 'Sensors are offline',
  sensor_outdated: 'Sensors are outdated',
  no_eligible_sensor: 'No sensor can take the run',
  credentials_missing: 'A credential is missing',
  quota_exhausted: 'Shared scanning quota used up',
  not_claimed: 'No sensor took the last runs',
  content_missing: 'A wordlist is missing',
}

function useStageText() {
  const { t } = useTranslation()
  return useMemo(
    () => ({
      label: (s: DiscoveryStage) => t(`attackSurface.discovery.stage.${s}`, STAGE_LABEL[s]),
      description: (s: DiscoveryStage) =>
        t(`attackSurface.discovery.stageDescription.${s}`, STAGE_DESCRIPTION[s]),
      status: (s: DiscoveryStatus) => t(`attackSurface.discovery.status.${s}`, STATUS_LABEL[s]),
      reason: (r: string) => t(`attackSurface.discovery.reason.${r}`, REASON_LABEL[r] ?? r),
    }),
    [t]
  )
}

interface StageCardProps {
  index: number
  row: DiscoveryStageRow
  canRun: boolean
  blockedReason?: string
  busy: boolean
  onRun: (stage: DiscoveryStage) => void
}

function StageCard({ index, row, canRun, blockedReason, busy, onRun }: StageCardProps) {
  const { t } = useTranslation()
  const text = useStageText()
  const limited = runLimited(row)
  const unit =
    row.progress_unit === 'tasks'
      ? t('attackSurface.discovery.progress.tasks', '{done} of {total} tasks', {
          done: row.progress_done,
          total: row.progress_total,
        })
      : t('attackSurface.discovery.progress.pairs', '{done} of {total} checks covered', {
          done: row.progress_done,
          total: row.progress_total,
        })
  const runReason = !canRun
    ? t(
        'attackSurface.discovery.run.noPermission',
        'Running a stage needs the scan execute permission.'
      )
    : (blockedReason ??
      (limited
        ? t('attackSurface.discovery.run.limited', 'This stage was run less than a minute ago.')
        : undefined))
  return (
    <Card data-testid={`discovery-stage-${row.stage}`} data-status={row.status}>
      <CardHeader className="gap-2 pb-3">
        <div className="flex items-start justify-between gap-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <span
              aria-hidden
              className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold"
            >
              {index + 1}
            </span>
            {text.label(row.stage)}
          </CardTitle>
          <TonePill
            tone={STATUS_TONE[row.status]}
            state={row.status}
            label={text.status(row.status)}
            detail={row.reason ? text.reason(row.reason) : undefined}
          />
        </div>
        <p className="text-sm text-muted-foreground">{text.description(row.stage)}</p>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <KeyValueList
          size="meta"
          items={[
            {
              key: 'last_run',
              label: t('attackSurface.discovery.lastRun', 'Last run'),
              value: row.last_run_at ? (
                <RelativeTime date={row.last_run_at} />
              ) : (
                t('attackSurface.discovery.never', 'Never')
              ),
            },
            ...(row.auto_validated_assets !== undefined
              ? [
                  {
                    key: 'auto_validated',
                    label: t('attackSurface.discovery.autoValidated', 'Last auto-validation'),
                    value: (
                      <span data-testid="discovery-auto-validated">
                        {t('attackSurface.discovery.autoValidatedCount', '{count} assets', {
                          count: row.auto_validated_assets,
                        })}
                      </span>
                    ),
                  },
                ]
              : []),
          ]}
        />
        <div className="flex flex-col gap-1">
          <Meter
            value={row.progress_done}
            max={row.progress_total}
            label={unit}
            tone={row.status === 'failed' ? 'destructive' : 'default'}
          />
          <span className="text-xs text-muted-foreground">{unit}</span>
        </div>
        <ul className="flex flex-col gap-1 text-xs">
          {row.capabilities.map((c) => (
            <li key={c.capability} className="flex items-center justify-between gap-2">
              <code className="truncate font-mono">{c.capability}</code>
              <span className="shrink-0 text-muted-foreground">
                {t('attackSurface.discovery.capabilityCounts', '{covered} of {pairs} covered', {
                  covered: c.covered,
                  pairs: c.pairs,
                })}
              </span>
            </li>
          ))}
        </ul>
        <GatedButton
          allowed={canRun && !blockedReason && !limited}
          reason={runReason ?? ''}
          variant="outline"
          size="sm"
          className="self-start"
          disabled={busy}
          onClick={() => onRun(row.stage)}
          aria-label={t('attackSurface.discovery.run.stageAria', 'Run {stage}', {
            stage: text.label(row.stage),
          })}
        >
          <Play className="me-2 h-4 w-4" aria-hidden />
          {t('attackSurface.discovery.run.stage', 'Run')}
        </GatedButton>
      </CardContent>
    </Card>
  )
}

export function EASMDiscovery() {
  const { t } = useTranslation()
  const text = useStageText()
  const { can } = usePermissions()
  const { overview, error, isLoading, isValidating, mutate, enabled } = useEASMDiscovery()
  const [busy, setBusy] = useState(false)
  const [confirmAbort, setConfirmAbort] = useState(false)
  const canRun = can(Permission.ScansWrite) && can(Permission.ScansExecute)
  const canAbort = can(Permission.ScansWrite)

  const blockedReason = !overview
    ? undefined
    : !overview.loop_enabled
      ? t('attackSurface.discovery.loopOff', 'Automatic coverage does not run on this server.')
      : !overview.coverage_enabled
        ? t(
            'attackSurface.discovery.coverageOff',
            'Automatic coverage is off for your organization. Turn it on in the scope settings to run stages.'
          )
        : overview.budget_used >= overview.daily_budget
          ? t('attackSurface.discovery.budgetSpent', "Today's coverage budget is used up.")
          : undefined

  const announce = useCallback(
    (started: DiscoveryStage[], skipped: DiscoveryStage[], pairs: number) => {
      toast.success(
        t(
          'attackSurface.discovery.run.started',
          '{stages}: {count} checks are due and start with the next coverage pass.',
          { stages: started.map(text.label).join(', '), count: pairs }
        )
      )
      if (skipped.length > 0) {
        toast.info(
          t(
            'attackSurface.discovery.run.skipped',
            'Skipped, run less than a minute ago: {stages}',
            {
              stages: skipped.map(text.label).join(', '),
            }
          )
        )
      }
    },
    [t, text]
  )

  const runStage = useCallback(
    async (stage: DiscoveryStage) => {
      setBusy(true)
      try {
        const res = await runDiscoveryStage(stage)
        announce(res.started, res.skipped, res.pairs_made_due)
        await mutate()
      } catch (e) {
        toast.error(
          getErrorMessage(e, t('attackSurface.discovery.run.failed', 'Could not run the stage'))
        )
      } finally {
        setBusy(false)
      }
    },
    [announce, mutate, t]
  )

  const runAll = useCallback(async () => {
    setBusy(true)
    try {
      const res = await runAllDiscovery()
      announce(res.started, res.skipped, res.pairs_made_due)
      await mutate()
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('attackSurface.discovery.run.failed', 'Could not run the stage'))
      )
    } finally {
      setBusy(false)
    }
  }, [announce, mutate, t])

  const abortAll = useCallback(async () => {
    try {
      const res = await abortAllDiscovery()
      toast.success(
        t('attackSurface.discovery.abort.done', '{count} coverage runs canceled.', {
          count: res.canceled,
        })
      )
      setConfirmAbort(false)
      await mutate()
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('attackSurface.discovery.abort.failed', 'Could not abort the runs'))
      )
    }
  }, [mutate, t])

  const exportCsv = useCallback(() => {
    if (!overview) return
    downloadCsv(discoveryCsv(overview), 'discovery-stages.csv')
  }, [overview])

  if (!enabled) {
    return (
      <EmptyState
        icon={ShieldX}
        title={t('attackSurface.discovery.noAccess.title', 'Access denied')}
        description={t(
          'attackSurface.discovery.noAccess.description',
          "You don't have permission to view scans. Ask your administrator for access."
        )}
      />
    )
  }
  if (error && !overview) {
    return (
      <ErrorState
        title={t('attackSurface.discovery.error', 'the discovery stages')}
        error={error}
        onRetry={() => mutate()}
      />
    )
  }

  const running = anyRunning(overview)
  const runningCount = overview?.stages.filter((s) => s.status === 'running').length ?? 0
  const metrics: MetricStripItem[] = [
    {
      key: 'running',
      href: '/scans',
      label: t('attackSurface.discovery.metric.running', 'Stages running'),
      value: runningCount,
    },
    {
      key: 'auto',
      href: '/attack-surface/review',
      label: t('attackSurface.discovery.metric.autoValidated', 'Assets in last auto-validation'),
      value: overview?.auto_validation.assets ?? 0,
      description: t(
        'attackSurface.discovery.metric.autoValidatedHelp',
        'Assets whose attribution was decided automatically during the latest Validation & scoping run.'
      ),
    },
    {
      key: 'budget',
      href: '/scope',
      label: t('attackSurface.discovery.metric.budget', 'Daily budget used'),
      value: overview ? `${overview.budget_used} / ${overview.daily_budget}` : 0,
      tone: overview && overview.budget_used >= overview.daily_budget ? 'warning' : 'default',
      description: t(
        'attackSurface.discovery.metric.budgetHelp',
        'Checks started in the last 24 hours, out of the daily coverage budget.'
      ),
    },
  ]

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p
          className="flex items-center gap-2 text-sm text-muted-foreground"
          data-testid="discovery-freshness"
        >
          {overview ? (
            <>
              <span>{t('attackSurface.discovery.updated', 'Updated')}</span>
              <RelativeTime date={overview.generated_at} />
            </>
          ) : null}
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => mutate()}
            disabled={isValidating}
            aria-label={t('attackSurface.discovery.refresh', 'Refresh')}
          >
            <RefreshCw className="h-4 w-4" aria-hidden />
          </Button>
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={exportCsv} disabled={!overview}>
            <Download className="me-2 h-4 w-4" aria-hidden />
            {t('attackSurface.discovery.export', 'Export CSV')}
          </Button>
          <GatedButton
            allowed={canAbort && running}
            reason={
              !canAbort
                ? t(
                    'attackSurface.discovery.abort.noPermission',
                    'Aborting runs needs the scan manage permission.'
                  )
                : t('attackSurface.discovery.abort.nothing', 'No coverage run is active.')
            }
            variant="outline"
            size="sm"
            onClick={() => setConfirmAbort(true)}
          >
            <Square className="me-2 h-4 w-4" aria-hidden />
            {t('attackSurface.discovery.abort.button', 'Abort all')}
          </GatedButton>
          <GatedButton
            allowed={canRun && !blockedReason}
            reason={
              !canRun
                ? t(
                    'attackSurface.discovery.run.noPermission',
                    'Running a stage needs the scan execute permission.'
                  )
                : (blockedReason ?? '')
            }
            size="sm"
            disabled={busy || !overview}
            onClick={runAll}
          >
            <Play className="me-2 h-4 w-4" aria-hidden />
            {t('attackSurface.discovery.runAll', 'Run all')}
          </GatedButton>
        </div>
      </div>
      {blockedReason && (
        <Alert role="status">
          <Info className="h-4 w-4" aria-hidden />
          <AlertDescription>{blockedReason}</AlertDescription>
        </Alert>
      )}
      <MetricStrip loading={isLoading && !overview} items={metrics} />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {(overview?.stages ?? []).map((row, i) => (
          <StageCard
            key={row.stage}
            index={i}
            row={row}
            canRun={canRun}
            blockedReason={blockedReason}
            busy={busy}
            onRun={runStage}
          />
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        {t(
          'attackSurface.discovery.footnote',
          'Run makes a stage due now; the next coverage pass, within {seconds} seconds, starts it through your scope rules and the daily budget.',
          { seconds: overview?.pass_every_seconds ?? 60 }
        )}
      </p>
      <ConfirmDialog
        open={confirmAbort}
        onOpenChange={setConfirmAbort}
        title={t('attackSurface.discovery.abort.title', 'Abort every coverage run?')}
        desc={t(
          'attackSurface.discovery.abort.description',
          "The organization's active coverage runs are canceled and their sensors told to stop. Your own scans are not touched. Automatic coverage keeps its schedule."
        )}
        confirmText={t('attackSurface.discovery.abort.confirm', 'Abort all')}
        destructive
        handleConfirm={abortAll}
      />
    </>
  )
}
