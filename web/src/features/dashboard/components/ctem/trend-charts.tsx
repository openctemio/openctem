'use client'

/**
 * The CTEM dashboard's two trend charts, in their own module so the cards can
 * load them with next/dynamic. Imported statically, they put recharts (about
 * 145 KB gzipped) into the dashboard's first-load JS, ahead of the numbers the
 * cards show without it.
 */

import {
  AreaChart,
  Area,
  LineChart,
  Line,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
} from '@/components/charts'
import type { RiskTrendPoint } from '../../hooks/use-ctem-dashboard'
import { CHART_TOOLTIP_PROPS, PRIORITY_CHART_COLORS, PRIORITY_ORDER } from '../../lib/ctem-colors'

function dateLabel(v: unknown): string {
  return new Date(String(v)).toLocaleDateString()
}

/** P0-open sparkline of the Active exposure card. */
export function P0TrendLine({ series }: { series: { date: string; p0: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={series} margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
        <XAxis dataKey="date" hide />
        <YAxis hide domain={[0, 'dataMax + 1']} />
        <Tooltip
          {...CHART_TOOLTIP_PROPS}
          labelFormatter={dateLabel}
          formatter={(value) => [value as number, 'P0 open']}
        />
        <Line
          type="monotone"
          dataKey="p0"
          stroke={PRIORITY_CHART_COLORS.P0}
          strokeWidth={2}
          dot={false}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}

/** Stacked P0-P3 open area chart of the Priority classes card. */
export function PriorityAreaChart({ points }: { points: RiskTrendPoint[] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={points} margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
        <XAxis dataKey="date" hide />
        <YAxis hide />
        <Tooltip {...CHART_TOOLTIP_PROPS} labelFormatter={dateLabel} />
        {PRIORITY_ORDER.map((p) => (
          <Area
            key={p}
            type="monotone"
            dataKey={`${p.toLowerCase()}_open`}
            name={p}
            stackId="1"
            stroke={PRIORITY_CHART_COLORS[p]}
            fill={PRIORITY_CHART_COLORS[p]}
            fillOpacity={0.6}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  )
}
