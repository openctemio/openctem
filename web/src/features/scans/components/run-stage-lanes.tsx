'use client'

import { useMemo } from 'react'
import useSWR from 'swr'
import { ArrowRight, Link2 } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { TruncatedText } from '@/features/shared'
import { get } from '@/lib/api/client'
import { pipelineRunEndpoints } from '@/lib/api/endpoints'
import type { RunStage, RunStageList } from '@/lib/api/generated'
import { useCapabilityTable } from '@/features/pipelines/lib/use-capability-table'

/** Why the hop router left targets out (scan_run_targets reasons). */
const SKIP_LABELS: Record<string, string> = {
  excluded: 'excluded by scope',
  unconfirmed: 'ownership not confirmed',
  refused: 'refused by the target check',
  other_zone: 'in another scan zone',
  hop_limit: 'too many hops from the seeds',
  over_cap: 'over the fan-out cap',
  duplicate: 'duplicates',
  invalid: 'not a valid target',
  incompatible_type: 'type the tool cannot scan',
}

const TIER_LABELS: Record<string, string> = {
  T0: 'Passive',
  T1: 'Active',
  T2: 'Intrusive',
}

/**
 * A stage's label: its capability name as GET /api/v1/scans/stages serves
 * it, else the key itself.
 */
/**
 * A stage's chunks in one line, from the API's counts: "3 of 10 chunks
 * done, 2 running, 4 queued, 1 failed". Empty for a stage of one command.
 */
export function chunkSummary(c?: RunStage['chunks']): string {
  if (!c || (c.total ?? 0) <= 1) return ''
  const parts = [`${c.completed ?? 0} of ${c.total} chunks done`]
  if (c.running) parts.push(`${c.running} running`)
  if (c.queued) parts.push(`${c.queued} queued`)
  if (c.failed) parts.push(`${c.failed} failed`)
  return parts.join(', ')
}

export function stageLabel(stage?: string, names?: Record<string, string>): string {
  if (!stage) return 'Custom step'
  return names?.[stage] ?? stage
}

export function skipLabel(reason: string): string {
  return SKIP_LABELS[reason] ?? reason.replace(/_/g, ' ')
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
 * left out. Counts come from GET /pipeline-runs/{id}/stages; nothing is
 * derived here.
 */
export function RunStageLanes({
  runId,
  refreshInterval,
}: {
  runId: string
  refreshInterval?: number
}) {
  const { table } = useCapabilityTable()
  const names = useMemo(
    () => Object.fromEntries(table.capabilities.map((c) => [c.key, c.name])),
    [table]
  )
  const { data, error, isLoading } = useSWR<RunStageList>(
    pipelineRunEndpoints.stages(runId),
    (url: string) => get<RunStageList>(url),
    { revalidateOnFocus: false, refreshInterval }
  )
  if (isLoading) return <Skeleton className="h-16 w-full" />
  if (error)
    return <p className="text-sm text-destructive">Could not load the stages of this run.</p>
  const lanes = data?.data ?? []
  if (lanes.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No stage of this run has been planned yet.</p>
    )
  }
  return (
    <ol className="space-y-2" aria-label="Stages of this run">
      {lanes.map((lane) => (
        <StageLane key={lane.stage_key} lane={lane} names={names} />
      ))}
    </ol>
  )
}

function StageLane({ lane, names }: { lane: RunStage; names: Record<string, string> }) {
  const reasons = skippedReasons(lane.skipped)
  const tier = lane.tier ?? 'T0'
  return (
    <li className="rounded-md border p-3" data-testid="stage-lane">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{stageLabel(lane.stage, names)}</span>
        <TruncatedText
          value={lane.tool}
          label="Tool"
          className="max-w-[160px] text-xs text-muted-foreground"
        />
        <Badge variant={tier === 'T0' ? 'secondary' : 'outline'} title={`Tier ${tier}`}>
          {tier} {TIER_LABELS[tier] ?? ''}
        </Badge>
        {lane.chained && (
          <Badge variant="outline" className="gap-1">
            <Link2 className="h-3 w-3" aria-hidden="true" />
            chained
          </Badge>
        )}
        <span className="ms-auto text-xs text-muted-foreground">
          <TruncatedText value={lane.stage_key} label="Step" className="max-w-[160px]" />
        </span>
      </div>
      <div className="mt-2 flex items-center gap-2 text-sm tabular-nums">
        <span>
          <span className="text-muted-foreground">In</span> {lane.inputs ?? 0}
        </span>
        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
        <span>
          <span className="text-muted-foreground">planned</span> {lane.planned ?? 0}
        </span>
        {lane.chained && (lane.max_hop ?? 0) > 0 && (
          <span className="text-xs text-muted-foreground">
            up to {lane.max_hop} hop(s) from the seeds
          </span>
        )}
      </div>
      {chunkSummary(lane.chunks) && (
        <div className="mt-2 text-xs" data-testid="stage-chunks">
          <p className="tabular-nums text-muted-foreground">{chunkSummary(lane.chunks)}</p>
          {(lane.sensors?.length ?? 0) > 0 && (
            <ul className="mt-1 space-y-0.5" aria-label="Chunks by sensor">
              {lane.sensors!.map((s, i) => (
                <li key={s.sensor_id ?? `platform-${i}`} className="flex items-center gap-2">
                  {s.platform ? (
                    <span>Platform sensors</span>
                  ) : (
                    <TruncatedText
                      value={s.sensor_name || s.sensor_id || 'Sensor'}
                      label="Sensor"
                      className="max-w-[180px]"
                    />
                  )}
                  <span className="ms-auto tabular-nums text-muted-foreground">
                    {s.total} chunk(s){s.completed ? `, ${s.completed} done` : ''}
                    {s.running ? `, ${s.running} running` : ''}
                    {s.failed ? `, ${s.failed} failed` : ''}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {reasons.length > 0 && (
        <ul className="mt-2 flex flex-wrap gap-1.5" aria-label="Skipped targets by reason">
          {reasons.map(([reason, n]) => (
            <li key={reason}>
              <Badge variant="outline" className="font-normal">
                <span className="tabular-nums">{n}</span>&nbsp;{skipLabel(reason)}
              </Badge>
            </li>
          ))}
        </ul>
      )}
    </li>
  )
}
