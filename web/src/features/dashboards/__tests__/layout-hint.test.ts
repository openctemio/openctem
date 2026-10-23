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
    const layout = [
      w('w_ct1', 'exposure.priority_open'),
      w('w_ct2', 'intel.kev_open'),
      w('w_ct3', 'crown_jewels.exposed'),
      w('w_ct5', 'ctem.loop'),
    ]
    const hint = layoutHintFor({ layout, kind: 'personal' })
    expect(hint?.template).toBe('ctem')
    expect(hint?.missing[0]).toBe('sla.within')
    expect(hint?.missing).toContain('coverage.discovery')
    const next = withTemplateWidgets(layout, templateByKey('ctem'), hint!.missing)
    // Nothing removed, nothing duplicated, the person's extra widget kept.
    expect(next.map((x) => (x.config as { id: string }).id)).toContain('w_ct3')
    const metrics = next.map((x) => (x.config as { data: { metric: string } }).data.metric)
    expect(new Set(metrics).size).toBe(metrics.length)
    expect(metrics.slice(0, 6)).toEqual([
      'exposure.priority_open',
      'intel.kev_open',
      'sla.within',
      'fix.time_to_fix',
      'crown_jewels.exposed',
      'ctem.loop',
    ])
    expect(next.map((x) => x.y)).toEqual(next.map((_, i) => i))
  })

  it('a widget id already taken gets a fresh one', () => {
    const layout = [
      w('w_ov1', 'exposure.priority_open'),
      w('w_ov2', 'intel.kev_open'),
      w('w_ov11', 'findings.open'),
    ]
    const hint = layoutHintFor({ layout, kind: 'personal' })!
    const next = withTemplateWidgets(layout, templateByKey('overview'), hint.missing)
    const ids = next.map((x) => (x.config as { id: string }).id)
    expect(new Set(ids).size).toBe(ids.length)
    expect(ids).toContain('w_ov11_2')
  })

  it('organization dashboards and non-template layouts get no hint', () => {
    const tpl = templateLayout(templateByKey('overview')).slice(0, 4)
    expect(layoutHintFor({ layout: tpl, kind: 'organization' })).toBeNull()
    expect(layoutHintFor({ layout: [w('a', 'findings.open')], kind: 'personal' })).toBeNull()
  })
})
