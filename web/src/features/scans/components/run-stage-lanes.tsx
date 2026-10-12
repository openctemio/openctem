'use client'

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { enTranslate, type Translate } from '../lib/translate'
import useSWR from 'swr'
import { ArrowRight, Link2 } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { TruncatedText } from '@/features/shared'
import { get } from '@/lib/api/client'
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type { RunStage, RunStageList } from '@/lib/api/generated'
import { useCapabilityTable } from '@/features/scan-workflows/lib/use-capability-table'

/** Why the hop router left targets out (scan_run_targets reasons) have labels under scans.stage.skip. */
const SKIP_REASONS = new Set([
  'excluded',
  'unconfirmed',
  'refused',
  'other_zone',
  'hop_limit',
  'over_cap',
  'duplicate',
  'invalid',
  'incompatible_type',
])

/**
 * A stage's label: its capability name as GET /api/v1/scans/stages serves
 * it, else the key itself.
 */
/**
 * A stage's chunks in one line, from the API's counts: "3 of 10 chunks
 * done, 2 running, 4 queued, 1 failed". Empty for a stage of one command.
 */
export function chunkSummary(c?: RunStage['chunks'], t: Translate = enTranslate): string {
  if (!c || (c.total ?? 0) <= 1) return ''
  const parts = [
    t('scans.stage.chunksDone', undefined, { done: c.completed ?? 0, total: c.total ?? 0 }),
  ]
  if (c.running) parts.push(t('scans.stage.running', undefined, { count: c.running }))
  if (c.queued) parts.push(t('scans.stage.queued', undefined, { count: c.queued }))
  if (c.failed) parts.push(t('scans.stage.failed', undefined, { count: c.failed }))
  return parts.join(', ')
}

export function stageLabel(
  stage?: string,
  names?: Record<string, string>,
  t: Translate = enTranslate
): string {
  if (!stage) return t('scans.stage.customStep')
  return names?.[stage] ?? stage
}

export function skipLabel(reason: string, t: Translate = enTranslate): string {
  return SKIP_REASONS.has(reason) ? t(`scans.stage.skip.${reason}`) : reason.replace(/_/g, ' ')
}

/** Skip reasons with a count, largest first (counts come from the API as-is). */
export function skippedReasons(skipped?: Record<string, number>): Array<[string, number]> {
  return Object.entries(skipped ?? {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
}

/**
 * One row per stage of a run (research/27 §9.3): what it ran, its tier,
 * how many targets it considered and was handed, and why the others were
 * left out. Counts come from GET /scan-runs/{id}/stages; nothing is
 * derived here.
 */
export function RunStageLanes({
  runId,
  refreshInterval,
}: {
  runId: string
  refreshInterval?: number
}) {
  const { t } = useTranslation()
  const { table } = useCapabilityTable()
  const names = useMemo(
    () => Object.fromEntries(table.capabilities.map((c) => [c.key, c.name])),
    [table]
  )
  const { data, error, isLoading } = useSWR<RunStageList>(
    scanRunEndpoints.stages(runId),
    (url: string) => get<RunStageList>(url),
    { revalidateOnFocus: false, refreshInterval }
  )
  if (isLoading) return <Skeleton className="h-16 w-full" />
  if (error) return <p className="text-sm text-destructive">{t('scans.stage.loadFailed')}</p>
  const lanes = data?.data ?? []
  if (lanes.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('scans.stage.none')}</p>
  }
  return (
    <ol className="space-y-2" aria-label={t('scans.stage.listLabel')}>
      {lanes.map((lane) => (
        <StageLane key={lane.stage_key} lane={lane} names={names} />
      ))}
    </ol>
  )
}

function StageLane({ lane, names }: { lane: RunStage; names: Record<string, string> }) {
  const { t } = useTranslation()
  const reasons = skippedReasons(lane.skipped)
  const tier = lane.tier ?? 'T0'
  return (
    <li className="rounded-md border p-3" data-testid="stage-lane">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{stageLabel(lane.stage, names, t)}</span>
        <TruncatedText
          value={lane.tool}
          label={t('scans.stage.tool')}
          className="max-w-[160px] text-xs text-muted-foreground"
        />
        <Badge
          variant={tier === 'T0' ? 'secondary' : 'outline'}
          title={t('scans.stage.tierTitle', undefined, { tier })}
        >
          {tier} {t(`scans.stage.tier.${tier}`, '')}
        </Badge>
        {lane.chained && (
          <Badge variant="outline" className="gap-1">
            <Link2 className="h-3 w-3" aria-hidden="true" />
            {t('scans.stage.chained')}
          </Badge>
        )}
        <span className="ms-auto text-xs text-muted-foreground">
          <TruncatedText
            value={lane.stage_key}
            label={t('scans.stage.step')}
            className="max-w-[160px]"
          />
        </span>
      </div>
      <div className="mt-2 flex items-center gap-2 text-sm tabular-nums">
        <span>
          <span className="text-muted-foreground">{t('scans.stage.in')}</span> {lane.inputs ?? 0}
        </span>
        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
        <span>
          <span className="text-muted-foreground">{t('scans.stage.planned')}</span>{' '}
          {lane.planned ?? 0}
        </span>
        {lane.chained && (lane.max_hop ?? 0) > 0 && (
          <span className="text-xs text-muted-foreground">
            {t('scans.stage.hops', undefined, { count: lane.max_hop ?? 0 })}
          </span>
        )}
      </div>
      {chunkSummary(lane.chunks, t) && (
        <div className="mt-2 text-xs" data-testid="stage-chunks">
          <p className="tabular-nums text-muted-foreground">{chunkSummary(lane.chunks, t)}</p>
          {(lane.sensors?.length ?? 0) > 0 && (
            <ul className="mt-1 space-y-0.5" aria-label={t('scans.stage.chunksBySensor')}>
              {lane.sensors!.map((s, i) => (
                <li key={s.sensor_id ?? `platform-${i}`} className="flex items-center gap-2">
                  {s.platform ? (
                    <span>{t('scans.stage.platform')}</span>
                  ) : (
                    <TruncatedText
                      value={s.sensor_name || s.sensor_id || t('scans.stage.sensor')}
                      label={t('scans.stage.sensor')}
                      className="max-w-[180px]"
                    />
                  )}
                  <span className="ms-auto tabular-nums text-muted-foreground">
                    {t('scans.stage.chunkCount', undefined, { count: s.total ?? 0 })}
                    {s.completed
                      ? t('scans.stage.chunkDone', undefined, { count: s.completed })
                      : ''}
                    {s.running
                      ? t('scans.stage.chunkRunning', undefined, { count: s.running })
                      : ''}
                    {s.failed ? t('scans.stage.chunkFailed', undefined, { count: s.failed }) : ''}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {reasons.length > 0 && (
        <ul className="mt-2 flex flex-wrap gap-1.5" aria-label={t('scans.stage.skippedByReason')}>
          {reasons.map(([reason, n]) => (
            <li key={reason}>
              <Badge variant="outline" className="font-normal">
                <span className="tabular-nums">{n}</span>&nbsp;{skipLabel(reason, t)}
              </Badge>
            </li>
          ))}
        </ul>
      )}
    </li>
  )
}
