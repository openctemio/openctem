import { describe, expect, it } from 'vitest'
import { phoneSpan } from '../layout'
import { templateDefects } from '../template-rules'
import { DASHBOARD_TEMPLATES, type DashboardTemplate } from '../templates'

/**
 * Every template follows the layout rules (template-rules.ts): allowed sizes
 * per visualization, headline first and the sections in order, at most ten
 * widgets, no two widgets with the same figures, full rows of one height and
 * one height band at four columns, and no hole at two columns or on a phone.
 */

const metricOf = (tpl: DashboardTemplate, i: number) =>
  (tpl.widgets[i].config as { data: { metric: string } }).data.metric

describe('template layouts', () => {
  it('has the five persona templates, CTEM first', () => {
    expect(DASHBOARD_TEMPLATES.map((t) => t.key)).toEqual([
      'ctem',
      'executive',
      'surface',
      'program',
      'triage',
    ])
  })

  for (const tpl of DASHBOARD_TEMPLATES) {
    it(`${tpl.key} follows the layout rules`, () => {
      expect(templateDefects(tpl)).toEqual([])
    })

    it(`${tpl.key}: the phone order is the template order, figures two by two`, () => {
      // The phone grid places widgets in the stored order; single figures
      // pair up, so they come in even runs and every other widget spans.
      let run = 0
      for (let i = 0; i < tpl.widgets.length; i++) {
        const w = tpl.widgets[i]
        if (phoneSpan(w.w, w.h, tpl.columns).startsWith('span 1')) run++
        else {
          expect(run % 2, `odd run of figures before ${metricOf(tpl, i)}`).toBe(0)
          run = 0
        }
      }
      expect(run % 2).toBe(0)
    })
  }

  it('the strip-led templates open on the key figures, then their hero', () => {
    const ctem = DASHBOARD_TEMPLATES.find((t) => t.key === 'ctem')!
    expect([metricOf(ctem, 0), metricOf(ctem, 1)]).toEqual(['exposure.kpis', 'exposure.flow'])
    const exec = DASHBOARD_TEMPLATES.find((t) => t.key === 'executive')!
    expect([metricOf(exec, 0), metricOf(exec, 1)]).toEqual([
      'exposure.kpis',
      'exposure.open_by_priority',
    ])
  })
})

describe('the rules catch a messy template', () => {
  const w = (id: string, metric: string, viz: string, ww: number, h: number) => ({
    widget_type: 'metric',
    w: ww,
    h,
    config: {
      v: 2,
      id,
      data: { kind: 'metric', metric, filter: {}, time: {} },
      viz: { type: viz },
    },
  })
  const messy: DashboardTemplate = {
    key: 'ctem',
    columns: 4,
    widgets: [
      w('a', 'exposure.flow', 'flow', 12, 4),
      w('b', 'exposure.kpis', 'kpi', 12, 1),
      w('c', 'fix.time_to_fix', 'bar', 6, 2),
      w('d', 'flow.new_vs_fixed', 'diverging', 6, 2),
      w('e', 'intel.kev_open', 'stat', 3, 1),
      w('f', 'brief.weekly', 'brief', 12, 1),
      w('g', 'exposure.levers', 'levers', 12, 1),
      w('h', 'flow.new_vs_fixed', 'column', 12, 2),
    ],
  }
  const defects = templateDefects(messy)
  it.each([
    'opens on a, not the headline figures',
    'c: bar at 6x2, allowed 6x1',
    'mixed bands in c+d',
    'hole after e',
    'h repeats d',
    'exposure.kpis and intel.kev_open show the same figures',
    'brief.weekly and exposure.levers show the same figures',
    'hole on a phone after e',
  ])('%s', (want) => {
    expect(defects).toContain(want)
  })
})
