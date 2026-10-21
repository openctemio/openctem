'use client'

/**
 * CSS-drawn visualizations: the heatmap (a matrix with every value printed,
 * shaded on one validated sequential ramp), the stage strip (the CTEM loop,
 * a remediation flow) and the items list (fix next, my SLA due).
 */

import { CheckCircle2, CircleMinus, TriangleAlert, XCircle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { SEQUENTIAL_STEPS, sequentialStep } from '@/lib/chart-palette'
import { formatCount, formatMetric, formatRelativeTime } from '@/lib/format-metric'
import { cn } from '@/lib/utils'
import { MatrixTable, StagesTable } from './table-viz'
import { ChartOrTable, DrillLink, useLabel } from './viz-parts'
import type { DrillFn, ItemsResult, MatrixResult, StageState, StagesResult } from './types'

/** The ramp step for a value between 0 and max (0 stays on the empty cell). */
export function heatStep(value: number, max: number): number {
  if (value <= 0 || max <= 0) return -1
  return Math.min(SEQUENTIAL_STEPS - 1, Math.floor((value / max) * SEQUENTIAL_STEPS))
}

export function HeatmapViz({ result, drill }: { result: MatrixResult; drill?: DrillFn }) {
  const { locale } = useTranslation()
  const label = useLabel()
  const max = Math.max(0, ...result.cells.flat().map((v) => v ?? 0))
  const chart = (
    <div
      className="grid gap-0.5 text-xs"
      style={{
        gridTemplateColumns: `minmax(5rem,auto) repeat(${result.cols.length}, minmax(2.5rem,1fr))`,
      }}
    >
      <span />
      {result.cols.map((c) => (
        <span key={c.key} className="truncate px-1 text-center text-muted-foreground">
          {label(c)}
        </span>
      ))}
      {result.rows.map((r, i) => (
        <div key={r.key} className="contents">
          <span className="truncate pe-2 text-muted-foreground">{label(r)}</span>
          {result.cols.map((c, j) => {
            const v = result.cells[i]?.[j] ?? null
            const step = v == null ? -1 : heatStep(v, max)
            const shade = step >= 0 ? sequentialStep(step) : null
            const text = `${label(r)} · ${label(c)}: ${formatCount(v, locale)}`
            const cell = (
              <span
                className={cn(
                  'flex h-8 items-center justify-center rounded-sm tabular-nums',
                  !shade && 'bg-muted text-muted-foreground'
                )}
                style={shade ? { background: shade.fill, color: shade.ink } : undefined}
                title={text}
              >
                {formatCount(v, locale)}
              </span>
            )
            return (
              <DrillLink
                key={c.key}
                to={v ? drill?.({ series: r.key, key: c.key }) : undefined}
                label={text}
              >
                {cell}
              </DrillLink>
            )
          })}
        </div>
      ))}
    </div>
  )
  return <ChartOrTable chart={chart} table={<MatrixTable result={result} drill={drill} />} />
}

const STAGE_ICON: Record<StageState, React.ReactNode> = {
  good: <CheckCircle2 className="size-3.5 text-success" aria-hidden />,
  warn: <TriangleAlert className="size-3.5 text-warning" aria-hidden />,
  crit: <XCircle className="size-3.5 text-destructive" aria-hidden />,
  unmeasured: <CircleMinus className="size-3.5 text-muted-foreground" aria-hidden />,
}

const STAGE_BAR: Record<StageState, string> = {
  good: 'bg-success',
  warn: 'bg-warning',
  crit: 'bg-destructive',
  unmeasured: 'bg-muted-foreground/40',
}

export function FunnelViz({ result }: { result: StagesResult }) {
  const { t, locale } = useTranslation()
  const label = useLabel()
  const stateText: Record<StageState, string> = {
    good: t('dashboardKit.stage.good', 'On track'),
    warn: t('dashboardKit.stage.warn', 'Needs attention'),
    crit: t('dashboardKit.stage.crit', 'Off track'),
    unmeasured: t('dashboardKit.stage.unmeasured', 'Not measured'),
  }
  const chart = (
    <ol className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
      {result.stages.map((s) => {
        const body = (
          <div className="flex h-full flex-col gap-1 overflow-hidden rounded-lg border p-2.5 hover:bg-accent/40">
            <span className={cn('-mx-2.5 -mt-2.5 mb-1 h-1', STAGE_BAR[s.state])} aria-hidden />
            <span className="text-xs text-muted-foreground">{label(s)}</span>
            <span
              className={cn(
                'text-xl font-semibold tabular-nums',
                s.value == null && 'text-muted-foreground'
              )}
            >
              {formatMetric(s.value, s.unit ?? 'count', locale)}
            </span>
            <span className="mt-auto inline-flex items-center gap-1 text-xs text-muted-foreground">
              {STAGE_ICON[s.state]}
              {s.value == null && s.reason_key ? t(s.reason_key) : stateText[s.state]}
            </span>
          </div>
        )
        return (
          <li key={s.key} data-state={s.state}>
            <DrillLink to={s.drill} className="block h-full rounded-lg">
              {body}
            </DrillLink>
          </li>
        )
      })}
    </ol>
  )
  return <ChartOrTable chart={chart} table={<StagesTable result={result} />} />
}

export function ItemsViz({
  result,
  viewAllHref,
  limit = 10,
}: {
  result: ItemsResult
  /** The full list in the same order and filter. */
  viewAllHref?: string
  limit?: number
}) {
  const { t, locale } = useTranslation()
  const rows = result.rows.slice(0, limit)
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-1">
      <ul className="flex flex-col divide-y">
        {rows.map((r) => {
          const due = r.due_at ? formatRelativeTime(r.due_at, locale) : null
          const body = (
            <div className="flex items-center gap-2 py-1.5 text-sm">
              {r.priority && (
                <Badge variant="outline" className="shrink-0 tabular-nums">
                  {r.priority}
                </Badge>
              )}
              {r.kev && (
                <Badge
                  variant="outline"
                  className="shrink-0 border-destructive/40 text-destructive"
                >
                  {t('dashboardKit.items.kev', 'KEV')}
                </Badge>
              )}
              <span className="min-w-0 flex-1 truncate">{r.title}</span>
              {r.asset && (
                <span className="hidden max-w-[10rem] truncate text-xs text-muted-foreground sm:inline">
                  {r.asset}
                </span>
              )}
              {due && (
                <span className="shrink-0 text-xs text-muted-foreground">
                  {t('dashboardKit.items.due', 'due {time}', { time: due })}
                </span>
              )}
            </div>
          )
          return (
            <li key={r.id}>
              <DrillLink to={r.href} className="block hover:bg-accent/40">
                {body}
              </DrillLink>
            </li>
          )
        })}
      </ul>
      {viewAllHref && (
        <DrillLink
          to={viewAllHref}
          className="mt-auto self-end pt-1 text-xs text-primary hover:underline"
        >
          {t('dashboardKit.items.viewAll', 'View all {n}', {
            n: formatCount(result.total, locale),
          })}
        </DrillLink>
      )}
    </div>
  )
}
