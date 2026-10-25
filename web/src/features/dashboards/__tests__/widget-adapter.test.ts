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

describe('exposure flow and intake', () => {
  const src = (tool: string, drill: string) => ({
    origin: 'sensor' as const,
    tool,
    receipts: 2,
    received: 10,
    created: 3,
    still_detected: 6,
    reopened: 0,
    closed: 0,
    suppressed: 1,
    not_stored: 1,
    last_at: '2026-10-25T10:00:00Z',
    last_status: 'completed',
    last_receipt_id: 'r1',
    health: 'ok' as const,
    drill,
  })
  const intake = {
    since: '2026-09-26T00:00:00Z',
    sources: [src('nuclei', '/findings/imports?origin=sensor&tool=nuclei'), src('x', 'javascript:alert(1)')],
    totals: { ...src('', '/findings/imports'), origin: '' as const, last_at: '0001-01-01T00:00:00Z' },
    noise: { received: 20, new: 4, merged: 12, suppressed: 2, not_stored: 2 },
    failing: 0,
    stale: 0,
    drill: '/findings/imports?since=2026-09-26T00:00:00Z',
    false_positive: { value: 3, drill: '/findings?status=false_positive' },
  }
  const fig = (value: number, drill: string) => ({ value, drill })

  it('maps the flow, keeping only same-origin lists', () => {
    const v: WidgetValue = {
      ...base,
      shape: 'flow',
      metric: 'exposure.flow',
      flow: {
        since: '2026-09-26T00:00:00Z',
        intake,
        actionable: fig(9, '/findings?state=open&priority_class=P0,P1,P2,P3'),
        classes: [{ key: 'P0', value: 9, drill: '//evil.example/x' }],
        open: fig(12, '/findings?state=open'),
        severity: [{ key: 'high', value: 12, drill: '/findings?state=open&severity=high' }],
        past_sla: fig(1, '/findings?state=open&sla_status=overdue'),
        in_progress: fig(2, '/findings?status=in_progress'),
        fixed: fig(3, '/findings?status=resolved'),
        accepted: fig(0, '/findings?status=accepted'),
        false_positive: fig(3, '/findings?status=false_positive'),
        stages: null,
      },
    }
    const m = widgetModel(v, spec('exposure.flow'), false)
    expect(m.state).toBe('ready')
    if (m.result?.shape !== 'flow') throw new Error('not flow')
    expect(m.result.actionable).toEqual({ key: undefined, value: 9, drill: '/findings?state=open&priority_class=P0,P1,P2,P3' })
    expect(m.result.classes[0].drill).toBeNull()
    expect(m.result.intake?.sources.map((s) => s.drill)).toEqual(['/findings/imports?origin=sensor&tool=nuclei', null])
    // A zero time is "never", not year 1.
    expect(m.result.intake?.totals.last_at).toBeNull()
    expect(m.result.stages).toBeNull()
  })

  it('a personal flow carries the reason instead of sources', () => {
    const v: WidgetValue = {
      ...base,
      shape: 'flow',
      flow: {
        since: '2026-09-26T00:00:00Z',
        intake_reason: 'organization_only',
        actionable: fig(0, '/findings'),
        classes: [],
        open: fig(0, '/findings'),
        severity: [],
        past_sla: fig(0, '/findings'),
        in_progress: fig(0, '/findings'),
        fixed: fig(0, '/findings'),
        accepted: fig(0, '/findings'),
        false_positive: fig(0, '/findings'),
        stages: null,
      },
    }
    const m = widgetModel(v, spec('exposure.flow'), false)
    if (m.result?.shape !== 'flow') throw new Error('not flow')
    expect(m.result.intake).toBeNull()
    expect(m.result.intake_reason_key).toBe('dashboards.reason.organization_only')
  })

  it('maps the intake; organization-only and no receipts are named reasons', () => {
    const m = widgetModel({ ...base, shape: 'intake', metric: 'ingest.intake', intake }, spec('ingest.intake'), false)
    if (m.result?.shape !== 'intake') throw new Error('not intake')
    expect(m.result.intake.noise.received).toBe(20)
    expect(m.result.intake.false_positive.drill).toBe('/findings?status=false_positive')
    expect(reasonKeyOf('organization_only')).toBe('dashboards.reason.organization_only')
    expect(reasonKeyOf('no_receipts')).toBe('dashboards.reason.no_receipts')
    const personal = widgetModel(
      { ...base, state: 'not_measured', reason: 'organization_only', shape: 'intake' },
      spec('ingest.intake'),
      false
    )
    expect(personal.state).toBe('not_measured')
    expect(personal.reasonKey).toBe('dashboards.reason.organization_only')
  })
})
