/**
 * The one set of chart defaults (web/docs/ui-style-contract.md, "Charts"):
 * axis, grid, hover cursor, tooltip box and plot heights. Every value is a
 * theme token, so a chart reads the same in light and dark. Series colours
 * are not here: they come from the `--viz-*` tokens by meaning (severity,
 * priority, category, new against fixed), never from a chart's own palette.
 */

/** Tick labels: the caption size in the muted ink. */
export const CHART_AXIS_TICK = { fill: 'var(--muted-foreground)', fontSize: 12 } as const

/** An axis draws its labels only: no axis line, no tick marks. */
export const CHART_AXIS = { tick: CHART_AXIS_TICK, axisLine: false, tickLine: false } as const

/** Horizontal guide lines only, dashed, in the border colour. */
export const CHART_GRID = {
  vertical: false,
  stroke: 'var(--border)',
  strokeDasharray: '3 3',
} as const

/** Column charts shade the hovered bucket; line and area charts draw a rule. */
export const CHART_BAR_CURSOR = { fill: 'var(--muted)', opacity: 0.5 } as const
export const CHART_LINE_CURSOR = { stroke: 'var(--border)', strokeWidth: 1 } as const

/** A marker or target line and its label. */
export const CHART_REFERENCE = {
  stroke: 'var(--muted-foreground)',
  strokeDasharray: '4 3',
} as const
export const CHART_REFERENCE_LABEL = { fill: 'var(--muted-foreground)', fontSize: 11 } as const

/** The tooltip box of a chart that uses the library's own tooltip. */
export const CHART_TOOLTIP_PROPS = {
  contentStyle: {
    backgroundColor: 'var(--popover)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    fontSize: 12,
    color: 'var(--popover-foreground)',
  },
  labelStyle: { color: 'var(--popover-foreground)' },
  itemStyle: { color: 'var(--popover-foreground)' },
} as const

/** Plot height of a chart in a widget, and of the same chart on a phone. */
export const CHART_HEIGHT = 220
