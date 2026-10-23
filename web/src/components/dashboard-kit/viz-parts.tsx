'use client'

/**
 * Small parts the visualizations share: the polarity-aware delta, the target
 * chip, the sparkline, the legend, the chart/table toggle and label lookup.
 */

import { useEffect, useState, type ReactNode } from 'react'
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  CircleMinus,
  Table2,
  BarChart3,
  TriangleAlert,
  XCircle,
} from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { formatBucket, formatDelta, formatMetric, type MetricUnit } from '@/lib/format-metric'
import { safeInternalHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import { deltaTone, targetStatus, type TargetStatus } from './compare'
import type { MetricTarget, Polarity, SeriesPoint } from './types'

/** True when the person asked the system for reduced motion: charts then do not animate. */
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false)
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReduced(mq.matches)
    const on = (e: MediaQueryListEvent) => setReduced(e.matches)
    mq.addEventListener?.('change', on)
    return () => mq.removeEventListener?.('change', on)
  }, [])
  return reduced
}

/** A label from a message key, an explicit label, or the raw key. */
export function useLabel() {
  const { t } = useTranslation()
  return (item: { key: string; label_key?: string; label?: string }) =>
    item.label_key ? t(item.label_key, item.label ?? item.key) : (item.label ?? item.key)
}

const TONE_CLASS = {
  better: 'text-success',
  worse: 'text-destructive',
  flat: 'text-muted-foreground',
  neutral: 'text-muted-foreground',
} as const

/**
 * The change against the previous period, as text with an arrow: "▼ 12 vs
 * previous period". Colour follows the figure's polarity and is never the only
 * signal (the arrow and the words carry it too).
 */
export function DeltaText({
  delta,
  unit,
  polarity,
  comparedTo,
  previous,
}: {
  delta: number | null | undefined
  unit: MetricUnit
  polarity: Polarity
  /** The previous period's value, printed so the change has a base ("vs 41 previous period"). */
  previous?: number | null
  /** What the change is against (default: "vs previous period"). */
  comparedTo?: string
}) {
  const { t, locale } = useTranslation()
  if (delta == null || !Number.isFinite(delta)) return null
  const tone = deltaTone(delta, polarity)
  const Icon = delta > 0 ? ArrowUpRight : delta < 0 ? ArrowDownRight : ArrowRight
  const against =
    comparedTo ??
    (previous != null && Number.isFinite(previous)
      ? t('dashboardKit.delta.vsPreviousValue', 'vs {value} previous period', {
          value: formatMetric(previous, unit, locale),
        })
      : t('dashboardKit.delta.vsPrevious', 'vs previous period'))
  const verdict =
    tone === 'better'
      ? t('dashboardKit.delta.better', 'better')
      : tone === 'worse'
        ? t('dashboardKit.delta.worse', 'worse')
        : tone === 'flat'
          ? t('dashboardKit.delta.unchanged', 'unchanged')
          : null
  return (
    <p className={cn('flex items-center gap-1 text-xs', TONE_CLASS[tone])} data-tone={tone}>
      <Icon className="size-3.5 shrink-0" aria-hidden />
      <span className="tabular-nums">{formatDelta(delta, unit, locale)}</span>
      <span className="text-muted-foreground">{against}</span>
      {verdict && <span className="sr-only">({verdict})</span>}
    </p>
  )
}

const STATUS_ICON: Record<TargetStatus, ReactNode> = {
  met: <CheckCircle2 className="size-3.5" aria-hidden />,
  near: <TriangleAlert className="size-3.5" aria-hidden />,
  missed: <XCircle className="size-3.5" aria-hidden />,
  unmeasured: <CircleMinus className="size-3.5" aria-hidden />,
}

const STATUS_CLASS: Record<TargetStatus, string> = {
  met: 'text-success border-success/30',
  near: 'text-warning border-warning/40',
  missed: 'text-destructive border-destructive/30',
  unmeasured: 'text-muted-foreground border-border',
}

/** "target ≤ 0 ✓" — icon, words and colour together, never colour alone. */
export function TargetChip({
  value,
  target,
  unit,
}: {
  value: number | null | undefined
  target: MetricTarget | null | undefined
  unit: MetricUnit
}) {
  const { t, locale } = useTranslation()
  const status = targetStatus(value, target)
  if (!target || !status) return null
  const statusText = {
    met: t('dashboardKit.target.met', 'on target'),
    near: t('dashboardKit.target.near', 'close to target'),
    missed: t('dashboardKit.target.missed', 'off target'),
    unmeasured: t('dashboardKit.target.unmeasured', 'not measured'),
  }[status]
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs',
        STATUS_CLASS[status]
      )}
      data-status={status}
    >
      {STATUS_ICON[status]}
      <span>
        {t('dashboardKit.target.label', 'target {op} {value}', {
          op: target.op,
          value: formatMetric(target.value, unit, locale),
        })}
      </span>
      <span className="sr-only">{statusText}</span>
    </span>
  )
}

/**
 * A small trend line whose ends are labelled: the first and last bucket's
 * date and value are printed under the line, so the trend is readable and
 * never decorative. Screen readers get the same as one sentence. Needs two
 * points or more; with fewer nothing is drawn.
 */
export function Sparkline({
  points,
  unit = 'count',
  bucket = 'day',
  className,
  height = 32,
}: {
  points: SeriesPoint[] | undefined
  unit?: MetricUnit
  bucket?: 'day' | 'week' | 'month'
  className?: string
  height?: number
}) {
  const { t, locale } = useTranslation()
  if (!points || points.length < 2) return null
  const width = 120
  const vs = points.map((p) => p.v)
  const min = Math.min(...vs)
  const max = Math.max(...vs)
  const span = max - min || 1
  const step = width / (points.length - 1)
  const d = points
    .map((p, i) => {
      const x = i * step
      const y = height - 2 - ((p.v - min) / span) * (height - 4)
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')
  const first = points[0]
  const last = points[points.length - 1]
  const ends = [first, last].map((p) => ({
    date: formatBucket(p.t, bucket, locale),
    value: formatMetric(p.v, unit, locale),
  }))
  const summary = t(
    'dashboardKit.sparkline.summary',
    'Trend from {from} on {start} to {to} on {end}',
    {
      from: ends[0].value,
      start: ends[0].date,
      to: ends[1].value,
      end: ends[1].date,
    }
  )
  return (
    <figure className={cn('flex flex-col gap-0.5', className)} data-testid="sparkline">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        className="h-8 w-full text-muted-foreground"
        aria-hidden
        focusable="false"
      >
        <path
          d={d}
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      <figcaption className="flex justify-between gap-2 text-[11px] leading-tight text-muted-foreground">
        <span className="sr-only">{summary}</span>
        {ends.map((e, i) => (
          <span
            key={i}
            aria-hidden
            className={cn('flex flex-col tabular-nums', i === 1 && 'items-end text-end')}
          >
            <span className="font-medium text-foreground">{e.value}</span>
            <span>{e.date}</span>
          </span>
        ))}
      </figcaption>
    </figure>
  )
}

export interface LegendEntry {
  key: string
  label: string
  color: string
}

/** A legend for two or more series, in the series' own (fixed) order. */
export function Legend({ entries }: { entries: LegendEntry[] }) {
  if (entries.length < 2) return null
  return (
    <ul className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
      {entries.map((e) => (
        <li key={e.key} className="inline-flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm" style={{ background: e.color }} aria-hidden />
          {e.label}
        </li>
      ))}
    </ul>
  )
}

/**
 * Every chart can be read as a table: a toggle above the chart switches the
 * view. The table view is the accessible and exact form of the same figures.
 */
export function ChartOrTable({
  chart,
  table,
  summary,
  defaultView = 'chart',
}: {
  chart: ReactNode
  table: ReactNode
  /** One sentence that says what the chart shows (its accessible name). */
  summary?: string
  defaultView?: 'chart' | 'table'
}) {
  const { t } = useTranslation()
  const [view, setView] = useState<'chart' | 'table'>(defaultView)
  const toTable = view === 'chart'
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex justify-end">
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs text-muted-foreground"
          aria-pressed={!toTable}
          onClick={() => setView(toTable ? 'table' : 'chart')}
        >
          {toTable ? <Table2 aria-hidden /> : <BarChart3 aria-hidden />}
          {toTable
            ? t('dashboardKit.action.showTable', 'Show table')
            : t('dashboardKit.action.showChart', 'Show chart')}
        </Button>
      </div>
      {view === 'chart' ? (
        <div className="min-h-0 flex-1" role="figure" aria-label={summary}>
          {summary && (
            <p className="sr-only" data-testid="chart-summary">
              {summary}
            </p>
          )}
          {chart}
        </div>
      ) : (
        <div className="min-h-0 flex-1">{table}</div>
      )}
    </div>
  )
}

/** Limits a list of rows to `slots`, folding the rest into one "Other" row. */
export function foldOther<T extends { key: string; value: number }>(
  rows: T[],
  slots: number,
  makeOther: (value: number) => T
): T[] {
  if (rows.length <= slots) return rows
  const kept = rows.slice(0, slots - 1)
  const rest = rows.slice(slots - 1).reduce((s, r) => s + r.value, 0)
  return [...kept, makeOther(rest)]
}

/**
 * A mark or row that opens its list. `to` comes from a drill builder or the
 * server, so it is reduced to a same-origin path; without one (or with an
 * unsafe one) the content renders as plain text in the same box.
 */
export function DrillLink({
  to,
  label,
  title,
  className,
  style,
  children,
}: {
  to: string | null | undefined
  label?: string
  title?: string
  className?: string
  style?: React.CSSProperties
  children?: ReactNode
}) {
  if (!safeInternalHref(to)) {
    return (
      <span className={className} style={style} title={title}>
        {children}
      </span>
    )
  }
  return (
    <Link
      href={safeInternalHref(to) ?? '/'}
      aria-label={label}
      title={title}
      className={cn('rounded-sm focus-visible:outline-2', className)}
      style={style}
    >
      {children}
    </Link>
  )
}
