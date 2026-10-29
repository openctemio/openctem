import { describe, expect, it } from 'vitest'
import type { DashboardWidget } from '../api/dashboards.types'
import { layoutHintFor, withTemplateWidgets } from '../layout-hint'
import { templateByKey, templateLayout } from '../templates'

const w = (id: string, metric: string): DashboardWidget => ({
  widget_type: 'metric',
  x: 0,
  y: 0,
  w: 3,
  h: 1,
  config: { v: 2, id, data: { kind: 'metric', metric, filter: {}, time: {} } },
})

describe('layout hint', () => {
  it('a current copy of each offered template has nothing missing', () => {
    for (const key of ['overview', 'ctem'] as const) {
      const layout = templateLayout(templateByKey(key))
      expect(layoutHintFor({ layout, kind: 'personal' })).toBeNull()
    }
  })

  it('an older CTEM copy is offered what it lacks, in template order', () => {
    // A copy of the previous CTEM template: four stat tiles and coverage
    // where the KPI strip is now, no levers and no brief.
    const layout = [
      w('w_ct20', 'exposure.flow'),
      w('w_ct1', 'exposure.priority_open'),
      w('w_ct2', 'intel.kev_open'),
      w('w_ct4', 'sla.within'),
      w('w_ct9', 'fix.time_to_fix'),
      w('w_ct10', 'coverage.discovery'),
      w('w_ct8', 'exposure.open_by_priority'),
      w('w_ct7', 'attack_paths.to_crown_jewels'),
      w('w_ct6', 'fix.next'),
      w('w_ct11', 'flow.new_vs_fixed'),
      w('w_ct12', 'findings.age_bands'),
      w('w_ct21', 'ingest.intake'),
      w('w_ct3', 'crown_jewels.exposed'),
    ]
    const hint = layoutHintFor({ layout, kind: 'personal' })
    expect(hint?.template).toBe('ctem')
    expect(hint?.missing).toEqual(['exposure.levers', 'exposure.kpis', 'brief.weekly'])
    const next = withTemplateWidgets(layout, templateByKey('ctem'), hint!.missing)
    const metrics = next.map((x) => (x.config as { data: { metric: string } }).data.metric)
    // Nothing removed, nothing duplicated, the person's extra widget kept.
    expect(new Set(metrics).size).toBe(metrics.length)
    expect(metrics).toContain('crown_jewels.exposed')
    expect(metrics.length).toBe(layout.length + 3)
    // The levers lead, the strip follows the flow, the brief sits beside the paths.
    expect(metrics.slice(0, 3)).toEqual(['exposure.levers', 'exposure.flow', 'exposure.kpis'])
    expect(metrics.indexOf('brief.weekly')).toBe(
      metrics.indexOf('attack_paths.to_crown_jewels') - 1
    )
    expect(next.map((x) => x.y)).toEqual(next.map((_, i) => i))
  })

  it('a widget id already taken gets a fresh one', () => {
    const layout = [
      w('w_ov1', 'exposure.priority_open'),
      w('w_ov2', 'intel.kev_open'),
      w('w_ov12', 'findings.open'),
    ]
    const hint = layoutHintFor({ layout, kind: 'personal' })!
    const next = withTemplateWidgets(layout, templateByKey('overview'), hint.missing)
    const ids = next.map((x) => (x.config as { id: string }).id)
    expect(new Set(ids).size).toBe(ids.length)
    expect(ids).toContain('w_ov12_2')
  })

  it('organization dashboards and non-template layouts get no hint', () => {
    const tpl = templateLayout(templateByKey('overview')).slice(0, 4)
    expect(layoutHintFor({ layout: tpl, kind: 'organization' })).toBeNull()
    expect(layoutHintFor({ layout: [w('a', 'findings.open')], kind: 'personal' })).toBeNull()
  })
})
