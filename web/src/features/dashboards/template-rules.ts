/**
 * The layout rules every dashboard template follows (docs/architecture/
 * dashboards.md, "Template layout rules"). `templateDefects` lists where a
 * template breaks them; the template-layouts test keeps the list empty.
 *
 * The grid has four columns from 1280px (`w` 3, 6 or 12 of the 12-unit
 * width), two from 640px, and a phone grid where one-row figures pair up
 * and everything else spans the row. Rows are at least 128px and grow to
 * their tallest widget, so a row must hold widgets of one height band:
 * a short bar list beside a chart would stretch into blank space.
 */

import { colSpanFor, phoneSpan } from './layout'
import type { DashboardTemplate } from './templates'

/**
 * Height band of a visualization: what it may share a row with.
 *  - figure: one number (stat, progress), in runs of four.
 *  - short: a bar list of a few rows (about 200px).
 *  - chart: a chart, matrix or list that fills its height (300-420px).
 *  - full: a strip, the hero diagram or a table; alone in its row.
 */
export type HeightBand = 'figure' | 'short' | 'chart' | 'full'

/** The sizes (12-unit width x rows) a template may give each visualization. */
export const TEMPLATE_SIZES: Readonly<Record<string, ReadonlyArray<readonly [number, number]>>> = {
  stat: [[3, 1]],
  progress: [[3, 1]],
  kpi: [[12, 1]],
  levers: [[12, 1]],
  brief: [[12, 1]],
  bar: [[6, 1]],
  donut: [[6, 2]],
  area: [
    [6, 2],
    [12, 2],
  ],
  line: [
    [6, 2],
    [12, 2],
  ],
  column: [
    [6, 2],
    [12, 2],
  ],
  diverging: [
    [6, 2],
    [12, 2],
  ],
  heatmap: [[6, 2]],
  paths: [[6, 2]],
  posture: [[6, 2]],
  list: [[12, 3]],
  table: [[12, 4]],
  flow: [[12, 4]],
  loop: [[12, 2]],
  intake: [[12, 3]],
}

const BAND: Readonly<Record<string, HeightBand>> = {
  stat: 'figure',
  progress: 'figure',
  bar: 'short',
  donut: 'chart',
  area: 'chart',
  line: 'chart',
  column: 'chart',
  diverging: 'chart',
  heatmap: 'chart',
  paths: 'chart',
  posture: 'chart',
}

export function heightBand(viz: string, w: number): HeightBand {
  if (w >= 12) return 'full'
  return BAND[viz] ?? 'full'
}

/** At most this many widgets per template: one screen of story, not a catalog. */
export const MAX_TEMPLATE_WIDGETS = 10

/**
 * Metrics that show the same figures: a template holds at most one of each
 * set. The key figures strip already carries the five single figures; the
 * weekly brief restates the biggest lever; the exposure flow carries the
 * sources (intake) and the five stages (loop).
 */
export const SAME_FIGURES: ReadonlyArray<readonly string[]> = [
  ['exposure.kpis', 'exposure.priority_open'],
  ['exposure.kpis', 'intel.kev_open'],
  ['exposure.kpis', 'sla.within'],
  ['exposure.kpis', 'coverage.discovery'],
  ['brief.weekly', 'exposure.levers'],
  ['exposure.flow', 'ingest.intake'],
  ['exposure.flow', 'ctem.loop'],
]

/** Order of the sections a template reads in. */
const SECTION_ORDER = ['headline', 'hero', 'act', 'trend', 'breakdown'] as const
type Section = (typeof SECTION_ORDER)[number]

/**
 * The section a widget belongs to: the headline figures; the hero visual
 * (the exposure flow, the posture, or a full-width chart); what to act on
 * (levers, brief, lists, attack paths to cut); trends; breakdowns.
 */
export function sectionOf(viz: string, w: number): Section {
  if (viz === 'kpi' || viz === 'stat' || viz === 'progress') return 'headline'
  if (viz === 'flow' || viz === 'posture' || viz === 'loop') return 'hero'
  if (['levers', 'brief', 'list', 'table', 'paths'].includes(viz)) return 'act'
  if (viz === 'bar' || viz === 'intake') return 'breakdown'
  return w >= 12 ? 'hero' : 'trend'
}

interface Cell {
  id: string
  metric: string
  viz: string
  w: number
  h: number
}

function cells(tpl: DashboardTemplate): Cell[] {
  return tpl.widgets.map((w) => {
    const c = w.config as { id: string; data: { metric?: string }; viz: { type: string } }
    return { id: c.id, metric: c.data.metric ?? '', viz: c.viz.type, w: w.w, h: w.h }
  })
}

/** Reading-order rows of `cols` columns (the grid does not back-fill). */
export function templateRows(
  tpl: DashboardTemplate,
  cols: number,
  spanOf: (w: number, h: number) => number
): Array<Array<Cell & { span: number }>> {
  const out: Array<Array<Cell & { span: number }>> = []
  let row: Array<Cell & { span: number }> = []
  let used = 0
  for (const c of cells(tpl)) {
    const span = spanOf(c.w, c.h)
    if (used + span > cols) {
      out.push(row)
      row = []
      used = 0
    }
    row.push({ ...c, span })
    used += span
  }
  if (row.length) out.push(row)
  return out
}

/** Every way the template breaks the rules (empty when it follows them). */
export function templateDefects(tpl: DashboardTemplate): string[] {
  const out: string[] = []
  const all = cells(tpl)
  const desk = (w: number) => colSpanFor(w, tpl.columns)

  if (tpl.columns !== 4) out.push(`columns ${tpl.columns}, templates use 4`)
  if (all.length > MAX_TEMPLATE_WIDGETS)
    out.push(`${all.length} widgets, at most ${MAX_TEMPLATE_WIDGETS}`)

  for (const c of all) {
    const sizes = TEMPLATE_SIZES[c.viz]
    if (!sizes) out.push(`${c.id}: no template size for ${c.viz}`)
    else if (!sizes.some(([w, h]) => w === c.w && h === c.h))
      out.push(
        `${c.id}: ${c.viz} at ${c.w}x${c.h}, allowed ${sizes.map((s) => s.join('x')).join(', ')}`
      )
  }

  // Headline first, then the sections in order.
  if (all.length && sectionOf(all[0].viz, all[0].w) !== 'headline')
    out.push(`opens on ${all[0].id}, not the headline figures`)
  let last = 0
  for (const c of all) {
    const at = SECTION_ORDER.indexOf(sectionOf(c.viz, c.w))
    if (at < last) out.push(`${c.id} (${SECTION_ORDER[at]}) after a ${SECTION_ORDER[last]} widget`)
    last = Math.max(last, at)
  }

  // One widget per figure set.
  const seen = new Map<string, string>()
  for (const c of all) {
    const spec = tpl.widgets.find((w) => (w.config as { id: string }).id === c.id)!.config as {
      data: { group_by?: string[]; filter?: unknown }
    }
    const key = `${c.metric}|${(spec.data.group_by ?? []).join(',')}|${JSON.stringify(spec.data.filter ?? {})}`
    if (seen.has(key)) out.push(`${c.id} repeats ${seen.get(key)}`)
    seen.set(key, c.id)
  }
  const metrics = new Set(all.map((c) => c.metric))
  for (const [a, b] of SAME_FIGURES)
    if (metrics.has(a) && metrics.has(b)) out.push(`${a} and ${b} show the same figures`)

  // Four columns: full rows, one height and one band per row.
  for (const row of templateRows(tpl, 4, desk)) {
    const ids = row.map((x) => x.id).join('+')
    if (row.reduce((n, x) => n + x.span, 0) < 4) out.push(`hole after ${ids}`)
    if (new Set(row.map((x) => x.h)).size > 1) out.push(`mixed heights in ${ids}`)
    if (new Set(row.map((x) => heightBand(x.viz, x.w))).size > 1) out.push(`mixed bands in ${ids}`)
  }
  // Two columns and the phone: no holes.
  for (const row of templateRows(tpl, 2, (w) => Math.min(2, desk(w))))
    if (row.reduce((n, x) => n + x.span, 0) < 2) out.push(`hole at two columns after ${row[0].id}`)
  const phone = (w: number, h: number) =>
    phoneSpan(w, h, tpl.columns).startsWith('span 1') ? 1 : 2
  for (const row of templateRows(tpl, 2, phone))
    if (row.reduce((n, x) => n + x.span, 0) < 2) out.push(`hole on a phone after ${row[0].id}`)
  return out
}
