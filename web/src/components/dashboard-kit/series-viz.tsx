'use client'

/**
 * Time-series visualizations: columns (flows such as opened or fixed per
 * bucket, stacked by series), area/line (stocks such as open findings over
 * time) and diverging bars (opened up, fixed down, with the net in words).
 * One y-axis only; every chart has a table view and a legend from two series.
 */

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from '@/components/charts'
import { useTranslation } from '@/context/i18n-provider'
import { seriesVar } from '@/lib/chart-palette'
import { formatBucket, formatCount, formatMetric, type MetricUnit } from '@/lib/format-metric'
import { safeInternalHref } from '@/lib/safe-href'
import { TimeSeriesTable } from './table-viz'
import { ChartOrTable, Legend, useLabel, usePrefersReducedMotion } from './viz-parts'
import type { DrillFn, TimeSeriesResult } from './types'

const AXIS_TICK = { fill: 'var(--muted-foreground)', fontSize: 12 }
const TOOLTIP_STYLE = {
  background: 'var(--popover)',
  color: 'var(--popover-foreground)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  fontSize: 12,
}
export const CHART_HEIGHT = 220
/** Plot height: shorter on a phone so a chart and its legend fit one screen. */
const PLOT_CLASS = 'h-[180px] sm:h-[220px]'

type Row = Record<string, number | string>

/** One row per bucket, one column per series key (missing points are absent, never 0). */
export function toRows(result: TimeSeriesResult, sign: Record<string, number> = {}): Row[] {
  const byT = new Map<string, Row>()
  for (const s of result.series) {
    for (const p of s.points) {
      const row = byT.get(p.t) ?? { t: p.t }
      row[s.key] = (sign[s.key] ?? 1) * p.v
      byT.set(p.t, row)
    }
  }
  return Array.from(byT.values()).sort((a, b) => String(a.t).localeCompare(String(b.t)))
}

function useSeriesMeta(result: TimeSeriesResult) {
  const label = useLabel()
  return result.series.map((s, i) => ({ key: s.key, label: label(s), color: seriesVar(s.key, i) }))
}

/** "Aug 7 to Oct 23. Latest: P0 20, P1 35, P2 42" — the accessible name of a series chart. */
function useSeriesSummary(result: TimeSeriesResult, unit: MetricUnit = 'count') {
  const { t, locale } = useTranslation()
  const label = useLabel()
  const ts = result.series.flatMap((s) => s.points.map((p) => p.t)).sort()
  if (ts.length === 0) return undefined
  const latest = result.series
    .map((s) => {
      const last = s.points[s.points.length - 1]
      return last ? `${label(s)} ${formatMetric(last.v, unit, locale)}` : null
    })
    .filter(Boolean)
    .join(', ')
  return t('dashboardKit.summary.series', '{from} to {to}. Latest: {values}', {
    from: formatBucket(ts[0], result.bucket, locale),
    to: formatBucket(ts[ts.length - 1], result.bucket, locale),
    values: latest,
  })
}

function useDrillNavigate(drill?: DrillFn) {
  const router = useRouter()
  return (sel: { series?: string; t?: string }) => {
    const href = safeInternalHref(drill?.(sel))
    if (href) router.push(href)
  }
}

interface SeriesVizProps {
  result: TimeSeriesResult
  unit?: MetricUnit
  drill?: DrillFn
}

export function ColumnViz({
  result,
  unit = 'count',
  drill,
  stacked = true,
}: SeriesVizProps & { stacked?: boolean }) {
  const { locale } = useTranslation()
  const reduced = usePrefersReducedMotion()
  const meta = useSeriesMeta(result)
  const rows = useMemo(() => toRows(result), [result])
  const go = useDrillNavigate(drill)
  const motion = reduced ? { isAnimationActive: false } : {}
  const summary = useSeriesSummary(result, unit)
  return (
    <ChartOrTable
      summary={summary}
      chart={
        <div className="flex flex-col gap-2">
          <div className={PLOT_CLASS}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={rows} margin={{ top: 4, right: 4, bottom: 0, left: -12 }}>
                <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 3" />
                <XAxis
                  dataKey="t"
                  tick={AXIS_TICK}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(v: string) => formatBucket(v, result.bucket, locale)}
                />
                <YAxis
                  tick={AXIS_TICK}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                  tickFormatter={(v: number) => formatCount(v, locale)}
                />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  cursor={{ fill: 'var(--muted)', opacity: 0.5 }}
                  labelFormatter={(v) => formatBucket(String(v), result.bucket, locale)}
                  formatter={(v) => formatMetric(Number(v), unit, locale)}
                />
                {meta.map((m, i) => (
                  <Bar
                    key={m.key}
                    dataKey={m.key}
                    name={m.label}
                    fill={m.color}
                    stackId={stacked ? 'a' : undefined}
                    stroke="var(--card)"
                    strokeWidth={1}
                    radius={!stacked || i === meta.length - 1 ? [4, 4, 0, 0] : 0}
                    cursor={drill ? 'pointer' : undefined}
                    onClick={(d: { payload?: Row }) =>
                      go({ series: m.key, t: String(d?.payload?.t ?? '') })
                    }
                    {...motion}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <Legend entries={meta} />
        </div>
      }
      table={<TimeSeriesTable result={result} unit={unit} drill={drill} />}
    />
  )
}

export function AreaLineViz({
  result,
  unit = 'count',
  drill,
  mode = 'area',
}: SeriesVizProps & { mode?: 'area' | 'line' }) {
  const { locale } = useTranslation()
  const label = useLabel()
  const reduced = usePrefersReducedMotion()
  const meta = useSeriesMeta(result)
  const rows = useMemo(() => toRows(result), [result])
  const go = useDrillNavigate(drill)
  const motion = reduced ? { isAnimationActive: false } : {}
  const summary = useSeriesSummary(result, unit)
  const common = {
    data: rows,
    margin: { top: 4, right: 4, bottom: 0, left: -12 },
    onClick: (s: { activeLabel?: string | number } | null) =>
      s?.activeLabel != null && go({ t: String(s.activeLabel) }),
  }
  const axes = (
    <>
      <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 3" />
      <XAxis
        dataKey="t"
        tick={AXIS_TICK}
        axisLine={false}
        tickLine={false}
        tickFormatter={(v: string) => formatBucket(v, result.bucket, locale)}
      />
      <YAxis
        tick={AXIS_TICK}
        axisLine={false}
        tickLine={false}
        allowDecimals={unit !== 'count'}
        tickFormatter={(v: number) => formatMetric(v, unit, locale)}
      />
      <Tooltip
        contentStyle={TOOLTIP_STYLE}
        labelFormatter={(v) => formatBucket(String(v), result.bucket, locale)}
        formatter={(v) => formatMetric(Number(v), unit, locale)}
      />
      {(result.markers ?? []).map((mk) => (
        <ReferenceLine
          key={mk.t}
          x={mk.t}
          stroke="var(--muted-foreground)"
          strokeDasharray="4 3"
          label={{
            value: label({ key: mk.t, ...mk }),
            fill: 'var(--muted-foreground)',
            fontSize: 11,
            position: 'insideTopLeft',
          }}
        />
      ))}
    </>
  )
  return (
    <ChartOrTable
      summary={summary}
      chart={
        <div className="flex flex-col gap-2">
          <div className={PLOT_CLASS}>
            <ResponsiveContainer width="100%" height="100%">
              {mode === 'area' ? (
                <AreaChart {...common}>
                  {axes}
                  {meta.map((m) => (
                    <Area
                      key={m.key}
                      dataKey={m.key}
                      name={m.label}
                      type="monotone"
                      stackId="a"
                      stroke={m.color}
                      strokeWidth={2}
                      fill={m.color}
                      fillOpacity={0.25}
                      {...motion}
                    />
                  ))}
                </AreaChart>
              ) : (
                <LineChart {...common}>
                  {axes}
                  {meta.map((m) => (
                    <Line
                      key={m.key}
                      dataKey={m.key}
                      name={m.label}
                      type="monotone"
                      stroke={m.color}
                      strokeWidth={2}
                      dot={false}
                      activeDot={{ r: 4 }}
                      {...motion}
                    />
                  ))}
                </LineChart>
              )}
            </ResponsiveContainer>
          </div>
          <Legend entries={meta} />
        </div>
      }
      table={<TimeSeriesTable result={result} unit={unit} drill={drill} />}
    />
  )
}

/** Net change of a flow pair over the period: opened minus fixed. */
export function netOf(result: TimeSeriesResult): number {
  const sum = (key: string) =>
    result.series.find((s) => s.key === key)?.points.reduce((a, p) => a + p.v, 0) ?? 0
  return sum('opened') - sum('fixed')
}

export function DivergingViz({ result, drill }: { result: TimeSeriesResult; drill?: DrillFn }) {
  const { t, locale } = useTranslation()
  const reduced = usePrefersReducedMotion()
  const meta = useSeriesMeta(result)
  const rows = useMemo(() => toRows(result, { fixed: -1 }), [result])
  const go = useDrillNavigate(drill)
  const motion = reduced ? { isAnimationActive: false } : {}
  const net = netOf(result)
  const summary =
    net < 0
      ? t('dashboardKit.flow.fixingFaster', 'Fixing faster than finding: {n} fewer open', {
          n: formatCount(-net, locale),
        })
      : net > 0
        ? t('dashboardKit.flow.findingFaster', 'Finding faster than fixing: {n} more open', {
            n: formatCount(net, locale),
          })
        : t('dashboardKit.flow.even', 'As many fixed as found')
  const range = useSeriesSummary(result)
  return (
    <ChartOrTable
      summary={
        range ? t('dashboardKit.summary.join', '{a}. {b}', { a: summary, b: range }) : summary
      }
      chart={
        <div className="flex flex-col gap-2">
          <p className="text-xs text-muted-foreground" aria-hidden>
            {summary}
          </p>
          <div className={PLOT_CLASS}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={rows}
                stackOffset="sign"
                margin={{ top: 4, right: 4, bottom: 0, left: -12 }}
              >
                <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 3" />
                <XAxis
                  dataKey="t"
                  tick={AXIS_TICK}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(v: string) => formatBucket(v, result.bucket, locale)}
                />
                <YAxis
                  tick={AXIS_TICK}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                  tickFormatter={(v: number) => formatCount(Math.abs(v), locale)}
                />
                <ReferenceLine y={0} stroke="var(--border)" />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  cursor={{ fill: 'var(--muted)', opacity: 0.5 }}
                  labelFormatter={(v) => formatBucket(String(v), result.bucket, locale)}
                  formatter={(v) => formatCount(Math.abs(Number(v)), locale)}
                />
                {meta.map((m) => (
                  <Bar
                    key={m.key}
                    dataKey={m.key}
                    name={m.label}
                    fill={m.color}
                    stackId="flow"
                    radius={m.key === 'fixed' ? [0, 0, 4, 4] : [4, 4, 0, 0]}
                    cursor={drill ? 'pointer' : undefined}
                    onClick={(d: { payload?: Row }) =>
                      go({ series: m.key, t: String(d?.payload?.t ?? '') })
                    }
                    {...motion}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <Legend entries={meta} />
        </div>
      }
      table={<TimeSeriesTable result={result} drill={drill} />}
    />
  )
}
