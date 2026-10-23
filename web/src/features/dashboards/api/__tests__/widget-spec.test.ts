import { describe, it, expect } from 'vitest'
import {
  isTypedWidget,
  keepOrDefaultViz,
  newMetricWidget,
  newWidgetId,
  vizzesFor,
  type CatalogMetric,
} from '../widget-spec'

const openFindings: CatalogMetric = {
  id: 'findings.open',
  group: 'exposure',
  filters: ['severity', 'source'],
  group_bys: ['severity', 'source'],
  max_group_by: 2,
  default_group_by: [],
  default_filter: {},
  polarity: 'lower_better',
  timed: false,
  flow: false,
  shapes: {
    '0': { shape: 'scalar', vizzes: ['stat', 'progress'] },
    '1': { shape: 'category', vizzes: ['bar', 'column', 'table', 'donut', 'stat'] },
    '2': { shape: 'matrix', vizzes: ['heatmap', 'table', 'column'] },
  },
}

describe('widget spec helpers', () => {
  it('widget ids match the server pattern and avoid taken ones', () => {
    const taken = new Set<string>()
    for (let i = 0; i < 200; i++) {
      const id = newWidgetId(taken)
      expect(id).toMatch(/^w_[a-z0-9]{1,16}$/)
      expect(taken.has(id)).toBe(false)
      taken.add(id)
    }
  })

  it('a new metric widget is typed and starts on the default visualization', () => {
    const w = newMetricWidget(openFindings, { x: 0, y: 0, w: 3, h: 2 })
    expect(isTypedWidget(w)).toBe(true)
    expect(w.config).toMatchObject({
      v: 2,
      data: { kind: 'metric', metric: 'findings.open' },
      viz: { type: 'stat' },
    })
    expect(isTypedWidget({ widget_type: 'open_findings' })).toBe(false)
  })

  it('a group-by change keeps a visualization that still fits, else takes the default', () => {
    expect(vizzesFor(openFindings, 1)[0]).toBe('bar')
    expect(keepOrDefaultViz(openFindings, 1, 'stat')).toBe('stat')
    expect(keepOrDefaultViz(openFindings, 2, 'donut')).toBe('heatmap')
    expect(keepOrDefaultViz(openFindings, 0, 'bar')).toBe('stat')
  })
})
