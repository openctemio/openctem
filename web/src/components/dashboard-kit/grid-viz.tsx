'use client'

/**
 * CSS-drawn visualizations: the heatmap (a matrix with every value printed,
 * shaded on one validated sequential ramp) and the items list (fix next, my
 * SLA due). The CTEM loop is loop-viz.tsx.
 */

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { SEQUENTIAL_STEPS, sequentialStep } from '@/lib/chart-palette'
import { formatCount, formatRelativeTime } from '@/lib/format-metric'
import { cn } from '@/lib/utils'
import { MatrixTable } from './table-viz'
import { ChartOrTable, DrillLink, useLabel } from './viz-parts'
import type { DrillFn, ItemsResult, MatrixResult } from './types'

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
              {r.title?.trim() ? (
                <span className="min-w-0 flex-1 truncate">{r.title}</span>
              ) : (
                <span className="min-w-0 flex-1 truncate text-muted-foreground">
                  {t('dashboardKit.items.untitled', 'Untitled finding')}
                </span>
              )}
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
