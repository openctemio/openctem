import { describe, expect, it } from 'vitest'
import { initHistory, push, redo, undo, HISTORY_LIMIT } from '../history'
import * as ops from '../layout-ops'
import {
  defaultSize,
  takesTarget,
  takesTime,
  withFilter,
  withGroupBy,
  withMetric,
  withViz,
} from '../spec-ops'
import type { CatalogMetric, WidgetSpec } from '../../api/widget-spec'
import type { DashboardWidget } from '../../api/dashboards.types'

const w = (id: string, width = 6, h = 2): DashboardWidget => ({
  widget_type: 'metric',
  x: 0,
  y: 0,
  w: width,
  h,
  config: {
    v: 2,
    id,
    data: { kind: 'metric', metric: 'findings.open', filter: {}, time: {} },
    viz: { type: 'stat', options: {} },
  },
})
const ids = (l: DashboardWidget[]) => l.map((x) => (x.config as { id: string }).id)

describe('history', () => {
  it('undo and redo walk the steps; a new step clears redo; the past is capped', () => {
    let h = initHistory(1)
    h = push(h, 2)
    h = push(h, 3)
    h = undo(h)
    expect(h.present).toBe(2)
    h = redo(h)
    expect(h.present).toBe(3)
    h = undo(push(undo(h), 9))
    expect(h.future).toEqual([9])
    expect(push(h, h.present)).toBe(h)
    let big = initHistory(0)
    for (let i = 1; i <= HISTORY_LIMIT + 10; i++) big = push(big, i)
    expect(big.past.length).toBe(HISTORY_LIMIT)
    expect(undo(initHistory(1)).present).toBe(1)
  })
})

describe('layout ops', () => {
  const l = [w('w_a'), w('w_b'), w('w_c')]
  it('moves within bounds and renumbers', () => {
    expect(ids(ops.move(l, 0, 2))).toEqual(['w_b', 'w_c', 'w_a'])
    expect(ids(ops.move(l, 0, -1))).toEqual(['w_a', 'w_b', 'w_c'])
    expect(ops.move(l, 2, 9).map((x) => x.y)).toEqual([0, 1, 2])
    expect(l.map((x) => x.y)).toEqual([0, 0, 0]) // input untouched
  })
  it('resizes by whole columns and rows within limits', () => {
    expect(ops.resizeWidth(l, 0, 1, 4)[0].w).toBe(9)
    expect(ops.resizeWidth([w('w_a', 12)], 0, 1, 4)[0].w).toBe(12)
    expect(ops.resizeWidth([w('w_a', 3)], 0, -1, 4)[0].w).toBe(3)
    expect(ops.resizeHeight(l, 0, 1)[0].h).toBe(3)
    expect(ops.resizeHeight([w('w_a', 6, ops.MAX_ROWS)], 0, 1)[0].h).toBe(ops.MAX_ROWS)
    expect(ops.resizeHeight([w('w_a', 6, 1)], 0, -1)[0].h).toBe(1)
  })
  it('duplicates with a fresh spec id and removes', () => {
    const d = ops.duplicate(l, 1)
    expect(d).toHaveLength(4)
    expect(ids(d)[2]).not.toBe('w_b')
    expect(ids(d)[2]).toMatch(/^w_[a-z0-9]{1,16}$/)
    expect(new Set(ids(d)).size).toBe(4)
    expect(ids(ops.remove(l, 1))).toEqual(['w_a', 'w_c'])
  })
})

const count: CatalogMetric = {
  id: 'findings.open',
  group: 'exposure',
  filters: ['severity', 'priority_class', 'kev', 'asset_group'],
  group_bys: ['severity', 'priority_class'],
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
const list: CatalogMetric = {
  ...count,
  id: 'fix.next',
  filters: ['asset_group'],
  group_bys: [],
  max_group_by: 0,
  shapes: { '0': { shape: 'items', vizzes: ['list', 'table'] } },
}
const spec: WidgetSpec = {
  v: 2,
  id: 'w_a',
  data: {
    kind: 'metric',
    metric: 'findings.open',
    filter: { severity: ['critical'] },
    time: { range: '90d' },
  },
  viz: { type: 'stat', options: {} },
  target: { op: '<=', value: 0 },
}

describe('spec ops', () => {
  it('a group-by keeps a visualization that still fits, else takes the default; drops a target', () => {
    const cat = withGroupBy(spec, count, ['severity'])
    expect(cat.viz.type).toBe('stat') // stat is valid for a category too
    expect(cat.target).toBeUndefined()
    const mat = withGroupBy(withViz(cat, count, 'bar'), count, ['severity', 'priority_class'])
    expect(mat.viz.type).toBe('heatmap')
    expect(withGroupBy(mat, count, []).data.group_by).toBeUndefined()
  })
  it('refuses a visualization the shape cannot draw', () => {
    expect(withViz(spec, count, 'heatmap')).toBe(spec)
  })
  it('switching to a list drops filters, time and target the list cannot take', () => {
    const next = withMetric(spec, list)
    expect(next.data.filter).toEqual({})
    expect(next.data.time).toEqual({})
    expect(next.viz.type).toBe('list')
    expect(next.target).toBeUndefined()
    expect(takesTime(next, list)).toBe(false)
    expect(takesTarget(spec, count)).toBe(true)
  })
  it('sets and clears filters', () => {
    expect(withFilter(spec, 'severity', []).data.filter).toEqual({})
    expect(withFilter(spec, 'kev', true).data.filter).toEqual({ severity: ['critical'], kev: true })
  })
  it('sizes new widgets by shape', () => {
    expect(defaultSize('scalar')).toEqual({ w: 3, h: 1 })
    expect(defaultSize('items')).toEqual({ w: 6, h: 3 })
    expect(defaultSize('time_series')).toEqual({ w: 6, h: 2 })
  })
})
