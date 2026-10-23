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
import { SEVERITY_DOT_COLORS, type SeverityLevel } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'
import { MatrixTable } from './table-viz'
import { ChartOrTable, DrillLink, useLabel } from './viz-parts'
import type { DrillFn, ItemsResult, MatrixResult } from './types'

/** The ramp step for a value between 0 and max (0 stays on the empty cell). */
export function heatStep(value: number, max: number): number {
  if (value <= 0 || max <= 0) return -1
  return Math.min(SEQUENTIAL_STEPS - 1, Math.floor((value / max) * SEQUENTIAL_STEPS))
}

const isSeverity = (k: string): k is SeverityLevel => k in SEVERITY_DOT_COLORS

export function HeatmapViz({ result, drill }: { result: MatrixResult; drill?: DrillFn }) {
  const { t, locale } = useTranslation()
  const label = useLabel()
  const max = Math.max(0, ...result.cells.flat().map((v) => v ?? 0))
  let peak: { r: number; c: number; v: number } | null = null
  result.cells.forEach((row, i) =>
    row.forEach((v, j) => {
      if (v != null && v > 0 && (!peak || v > peak.v)) peak = { r: i, c: j, v }
    })
  )
  const top = peak as { r: number; c: number; v: number } | null
  const summary = top
    ? t('dashboardKit.summary.matrix', 'Highest: {row}, {col}: {n}', {
        row: label(result.rows[top.r]),
        col: label(result.cols[top.c]),
        n: formatCount(top.v, locale),
      })
    : undefined
  const chart = (
    <div className="flex flex-col gap-2">
      <div
        className="grid gap-0.5 text-xs"
        style={{
          gridTemplateColumns: `minmax(4.5rem,auto) repeat(${result.cols.length}, minmax(2.25rem,1fr))`,
        }}
      >
        <span />
        {/* Column headers wrap (two short lines on a phone) instead of truncating. */}
        {result.cols.map((c) => (
          <span
            key={c.key}
            className="self-end px-0.5 text-center text-[11px] leading-tight break-words text-muted-foreground sm:text-xs"
          >
            {label(c)}
          </span>
        ))}
        {result.rows.map((r, i) => (
          <div key={r.key} className="contents">
            <span className="flex min-w-0 items-center gap-1.5 pe-2 text-muted-foreground">
              {isSeverity(r.key) && (
                <span
                  className={cn('size-2 shrink-0 rounded-full', SEVERITY_DOT_COLORS[r.key])}
                  aria-hidden
                />
              )}
              <span className="truncate">{label(r)}</span>
            </span>
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
      {max > 0 && (
        <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground" aria-hidden>
          <span>{t('dashboardKit.heatmap.fewer', 'Fewer')}</span>
          {Array.from({ length: SEQUENTIAL_STEPS }, (_, k) => (
            <span
              key={k}
              className="h-2.5 w-5 rounded-sm"
              style={{ background: sequentialStep(k).fill }}
            />
          ))}
          <span>{t('dashboardKit.heatmap.more', 'More')}</span>
          <span className="ms-auto tabular-nums">
            {t('dashboardKit.heatmap.max', 'max {n}', { n: formatCount(max, locale) })}
          </span>
        </div>
      )}
    </div>
  )
  return (
    <ChartOrTable
      summary={summary}
      chart={chart}
      table={<MatrixTable result={result} drill={drill} />}
    />
  )
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
