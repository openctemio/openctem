import { describe, expect, it } from 'vitest'
import { reasonKeyOf, specOf, widgetModel } from '../api/widget-adapter'
import type { WidgetValue } from '../api/widget-data'
import type { WidgetSpec } from '../api/widget-spec'

const spec = (metric: string, extra: Partial<WidgetSpec['data']> = {}): WidgetSpec => ({
  v: 2,
  id: 'w_a',
  data: { kind: 'metric', metric, filter: {}, time: {}, ...extra },
  viz: { type: 'stat', options: {} },
})

const base: WidgetValue = { id: 'w_a', index: 0, widget_type: 'metric', state: 'ready' }

describe('widgetModel', () => {
  it('a scalar keeps its previous period and drill-down; stale marks it', () => {
    const v: WidgetValue = {
      ...base,
      shape: 'scalar',
      metric: 'findings.open',
      drill: '/findings?state=open',
      scalar: { value: 31, previous: 43, delta: -12 },
    }
    const m = widgetModel(v, spec('findings.open'), false)
    expect(m.state).toBe('ready')
    expect(m.result).toMatchObject({ shape: 'scalar', value: 31, previous: 43, delta: -12 })
    expect(m.drill).toBe('/findings?state=open')
    expect(widgetModel(v, spec('findings.open'), true).state).toBe('stale')
  })

  it('drops an off-site drill-down', () => {
    const v: WidgetValue = {
      ...base,
      shape: 'scalar',
      drill: 'https://evil.example/x',
      scalar: { value: 1 },
    }
    expect(widgetModel(v, undefined, false).drill).toBeUndefined()
  })

  it('a ratio without a denominator is not measured, never 0 %', () => {
    const v: WidgetValue = {
      ...base,
      state: 'not_measured',
      reason: 'no_denominator',
      shape: 'ratio',
      ratio: { num: 0, den: 0, value_pct: null },
    }
    const m = widgetModel(v, spec('sla.within'), false)
    expect(m.state).toBe('not_measured')
    expect(m.reasonKey).toBe('dashboards.reason.no_denominator')
    expect(m.result).toMatchObject({ shape: 'ratio', value_pct: null })
  })

  it('category rows carry a translated label of their dimension and keep ordinal order', () => {
    const v: WidgetValue = {
      ...base,
      shape: 'category',
      category: {
        rows: [
          { key: 'critical', value: 2, drill: '/findings?severity=critical' },
          { key: 'low', value: 5 },
        ],
        total: 7,
      },
    }
    const m = widgetModel(v, spec('findings.open', { group_by: ['severity'] }), false)
    expect(m.result).toMatchObject({
      shape: 'category',
      ordinal: true,
      rows: [
        { key: 'critical', label_key: 'dashboards.dimension.severity.values.critical' },
        { key: 'low' },
      ],
    })
  })

  it('a matrix uses the metric default group-by when the widget names none', () => {
    const v: WidgetValue = {
      ...base,
      shape: 'matrix',
      matrix: { rows: ['high'], cols: ['90+'], cells: [[3]] },
    }
    const m = widgetModel(v, spec('findings.age_bands'), false)
    expect(m.result).toMatchObject({
      rows: [{ label_key: 'dashboards.dimension.severity.values.high' }],
      cols: [{ label_key: 'dashboards.dimension.age_band.values.90_' }],
    })
  })

  it('items open the finding; an empty list is "nothing to show", not an error', () => {
    const v: WidgetValue = {
      ...base,
      shape: 'items',
      items: {
        rows: [{ id: 'f/1', title: 'RCE', severity: 'critical', priority_class: 'P0', kev: true }],
      },
    }
    const m = widgetModel(v, spec('fix.next'), false)
    expect(m.result).toMatchObject({
      rows: [{ href: '/findings/f%2F1', kev: true, priority: 'P0' }],
    })
    // The row count is not the list total: no total until the server sends one.
    expect((m.result as { total?: number | null }).total).toBeNull()
    const sent = widgetModel({ ...v, items: { ...v.items!, total: 340 } }, spec('fix.next'), false)
    expect((sent.result as { total?: number | null }).total).toBe(340)
    const empty = widgetModel({ ...v, items: { rows: [] } }, spec('fix.next'), false)
    expect(empty.state).toBe('no_data_yet')
    expect(empty.reasonKey).toBe('dashboards.reason.empty')
  })

  it('maps building, unsupported and failed states', () => {
    expect(widgetModel({ ...base, state: 'building' }, undefined, false)).toMatchObject({
      state: 'no_data_yet',
      reasonKey: 'dashboards.reason.facts_building',
    })
    expect(
      widgetModel({ ...base, state: 'unsupported', reason: 'legacy_tile' }, undefined, false)
    ).toMatchObject({ state: 'not_measured', reasonKey: 'dashboards.reason.legacy_tile' })
    expect(widgetModel({ ...base, state: 'error' }, undefined, false).state).toBe('error')
    // ready but without its payload: an error, never a blank 0
    expect(widgetModel({ ...base, shape: 'scalar' }, undefined, false).state).toBe('error')
    expect(widgetModel(undefined, undefined, false).state).toBe('loading')
    expect(reasonKeyOf('something new')).toBe('dashboards.reason.failed')
    // CTEM metrics with nothing to measure explain why instead of "failed"
    expect(
      widgetModel({ ...base, state: 'not_measured', reason: 'no_crown_jewels' }, undefined, false)
    ).toMatchObject({ state: 'not_measured', reasonKey: 'dashboards.reason.no_crown_jewels' })
    expect(reasonKeyOf('no_relationship_data')).toBe('dashboards.reason.no_relationship_data')
  })

  it('flows are labelled new and fixed', () => {
    const v: WidgetValue = {
      ...base,
      shape: 'time_series',
      metric: 'flow.new_vs_fixed',
      series: { bucket: 'week', series: [{ key: 'opened', points: [{ t: '2026-10-05', v: 3 }] }] },
    }
    expect(widgetModel(v, spec('flow.new_vs_fixed'), false).result).toMatchObject({
      kind: 'flow',
      bucket: 'week',
      series: [{ label_key: 'dashboards.flow.opened' }],
    })
  })
})

describe('specOf', () => {
  it('reads a typed spec and ignores legacy tiles', () => {
    expect(specOf({ widget_type: 'open_findings' })).toBeUndefined()
    expect(specOf({ widget_type: 'metric', config: spec('findings.open') as never })?.id).toBe(
      'w_a'
    )
    expect(specOf({ widget_type: 'metric', config: {} })).toBeUndefined()
  })
})

describe('CTEM shapes', () => {
  it('maps the loop: stage names, states, reasons, second figures and the focus', () => {
    const v: WidgetValue = {
      id: 'w_l',
      index: 0,
      widget_type: 'metric',
      state: 'ready',
      shape: 'stages',
      metric: 'ctem.loop',
      stages: {
        focus: 1,
        stages: [
          {
            key: 'scoping',
            state: 'warn',
            value: 0,
            unit: 'count',
            drill: '/assets?is_crown_jewel=true',
            flag: 'designate_crown_jewels',
          },
          {
            key: 'discovery',
            state: 'not_measured',
            reason: 'no_tracked_assets',
            value: null,
            unit: 'percent',
            drill: '/assets?coverage=uncovered',
          },
          {
            key: 'mobilize',
            state: 'crit',
            value: 61.5,
            unit: 'percent',
            drill: 'https://evil.example/x',
            detail: { key: 'breached', value: 4, drill: '/findings?state=open' },
          },
        ],
      },
    }
    const m = widgetModel(v, spec('ctem.loop'), false)
    expect(m.state).toBe('ready')
    if (m.result?.shape !== 'stages') throw new Error('not stages')
    expect(m.result.focus).toBe(1)
    const [scoping, discovery, mobilize] = m.result.stages
    expect(scoping.label_key).toBe('dashboards.loop.stage.scoping')
    expect(scoping.flag_key).toBe('dashboards.loop.flag.designate_crown_jewels')
    expect(discovery.state).toBe('unmeasured')
    expect(discovery.value).toBeNull()
    expect(discovery.reason_key).toBe('dashboards.loop.reason.no_tracked_assets')
    // Only same-origin lists are linked.
    expect(mobilize.drill).toBeNull()
    expect(mobilize.detail).toEqual({
      label_key: 'dashboards.loop.detail.breached',
      value: 4,
      drill: '/findings?state=open',
    })
  })

  it('maps attack paths: rows open their asset, an empty list is not "no data"', () => {
    const v: WidgetValue = {
      id: 'w_p',
      index: 0,
      widget_type: 'metric',
      state: 'ready',
      shape: 'paths',
      metric: 'attack_paths.to_crown_jewels',
      drill: '/attack-paths',
      paths: { reachable: 0, designated: 3, rows: [] },
    }
    const m = widgetModel(v, spec('attack_paths.to_crown_jewels'), false)
    expect(m.state).toBe('ready')
    expect(m.drill).toBe('/attack-paths')
    const withRow = widgetModel(
      {
        ...v,
        paths: {
          reachable: 1,
          designated: 3,
          rows: [
            {
              asset_id: 'a/1',
              name: 'db',
              asset_type: 'host',
              criticality: 'critical',
              reachable_from: 2,
              entry_point: false,
              depth: 2,
              score: 9,
            },
          ],
        },
      },
      spec('attack_paths.to_crown_jewels'),
      false
    )
    if (withRow.result?.shape !== 'paths') throw new Error('not paths')
    expect(withRow.result.rows[0].href).toBe('/assets/a%2F1')
  })
})
