import { describe, expect, it } from 'vitest'
import { colSpanFor, phoneSpan } from '../layout'
import { DASHBOARD_TEMPLATES, type DashboardTemplate } from '../templates'

/**
 * Every template fills its rows without holes and keeps one height per row,
 * at each width the grid has: four columns (from 1280px), two (640-1279px)
 * and the phone's two (single figures pair up, everything else spans the
 * row). The grid places widgets in reading order without back-filling, so a
 * half-width widget followed by a full-width one leaves a hole.
 */

type Row = Array<{ id: string; span: number; h: number }>

function rows(tpl: DashboardTemplate, cols: number, spanOf: (w: number, h: number) => number) {
  const out: Row[] = []
  let row: Row = []
  let used = 0
  for (const w of tpl.widgets) {
    const span = spanOf(w.w, w.h)
    if (used + span > cols) {
      out.push(row)
      row = []
      used = 0
    }
    row.push({ id: String((w.config as { id: string }).id), span, h: w.h })
    used += span
  }
  if (row.length) out.push(row)
  return out
}

function defects(tpl: DashboardTemplate, cols: number, spanOf: (w: number, h: number) => number) {
  return rows(tpl, cols, spanOf).flatMap((row) => {
    const filled = row.reduce((n, x) => n + x.span, 0)
    const out: string[] = []
    if (filled < cols) out.push(`hole after ${row.map((x) => x.id).join('+')}`)
    if (new Set(row.map((x) => x.h)).size > 1)
      out.push(`mixed heights in ${row.map((x) => `${x.id}:${x.h}`).join('+')}`)
    return out
  })
}

describe('template layouts', () => {
  for (const tpl of DASHBOARD_TEMPLATES) {
    it(`${tpl.key}: no holes and one height per row at four columns`, () => {
      expect(defects(tpl, 4, (w) => colSpanFor(w, tpl.columns))).toEqual([])
    })
    it(`${tpl.key}: no holes at two columns`, () => {
      const spanOf = (w: number) => Math.min(2, colSpanFor(w, tpl.columns))
      expect(defects(tpl, 2, spanOf).filter((d) => d.startsWith('hole'))).toEqual([])
    })
    it(`${tpl.key}: no holes on a phone`, () => {
      const spanOf = (w: number, h: number) =>
        phoneSpan(w, h, tpl.columns).startsWith('span 1') ? 1 : 2
      expect(defects(tpl, 2, spanOf).filter((d) => d.startsWith('hole'))).toEqual([])
    })
  }

  it('each template opens on its headline figures, never on a tall diagram', () => {
    const first = (key: string) =>
      (
        DASHBOARD_TEMPLATES.find((t) => t.key === key)!.widgets[0].config as {
          data: { metric: string }
        }
      ).data.metric
    expect(first('ctem')).toBe('exposure.kpis')
    expect(first('overview')).toBe('exposure.kpis')
    expect(first('executive')).toBe('exposure.kpis')
    for (const tpl of DASHBOARD_TEMPLATES) expect(tpl.widgets[0].h).toBe(1)
  })
})
