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
    for (const key of ['ctem', 'executive', 'surface', 'program', 'triage'] as const) {
      const layout = templateLayout(templateByKey(key))
      expect(layoutHintFor({ layout, kind: 'personal' })).toBeNull()
    }
  })

  it('an older CTEM copy is offered what it lacks, in template order', () => {
    // A copy of an earlier CTEM template: four stat tiles and coverage
    // where the KPI strip is now, no levers.
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
    expect(hint?.missing).toEqual([
      'exposure.kpis',
      'ctem.loop',
      'exposure.levers',
      'surface.new_assets',
      'certificates.expiry',
    ])
    const next = withTemplateWidgets(layout, templateByKey('ctem'), hint!.missing)
    const metrics = next.map((x) => (x.config as { data: { metric: string } }).data.metric)
    // Nothing removed, nothing duplicated, the person's extra widget kept.
    expect(new Set(metrics).size).toBe(metrics.length)
    expect(metrics).toContain('crown_jewels.exposed')
    expect(metrics.length).toBe(layout.length + 5)
    // The key figures come before the stage row; the person's flow stays where it was.
    expect(metrics.indexOf('exposure.kpis')).toBeLessThan(metrics.indexOf('ctem.loop'))
    expect(metrics.indexOf('exposure.flow')).toBe(0)
    expect(next.map((x) => x.y)).toEqual(next.map((_, i) => i))
  })

  it('a copy of the previous default (flow first, full-width Fix next) is offered the new layout and is left as it is', () => {
    const at = (id: string, metric: string, ww: number, h: number): DashboardWidget => ({
      ...w(id, metric),
      w: ww,
      h,
    })
    const layout = [
      at('w_ct31', 'exposure.kpis', 12, 1),
      at('w_ct20', 'exposure.flow', 12, 4),
      at('w_ct30', 'exposure.levers', 12, 1),
      at('w_ct6', 'fix.next', 12, 3),
      at('w_ct7', 'attack_paths.to_crown_jewels', 6, 2),
      at('w_ct8', 'exposure.open_by_priority', 6, 2),
      at('w_ct11', 'flow.new_vs_fixed', 6, 2),
      at('w_ct12', 'findings.age_bands', 6, 2),
      at('w_ct40', 'surface.new_assets', 6, 1),
      at('w_ct41', 'certificates.expiry', 6, 1),
    ]
    const before = structuredClone(layout)
    const hint = layoutHintFor({ layout, kind: 'personal' })
    expect(hint).toMatchObject({ template: 'ctem', missing: ['ctem.loop'], rearranged: true })
    // Looking never edits the stored layout; only the person's choice does.
    expect(layout).toEqual(before)
    // Adding the missing widget keeps every existing one in place and size.
    const next = withTemplateWidgets(layout, templateByKey('ctem'), hint!.missing)
    expect(
      next.filter((x) => (x.config as { id: string }).id !== 'w_ct22').map((x) => [x.w, x.h])
    ).toEqual(before.map((x) => [x.w, x.h]))
    // A copy of the new default raises no hint.
    expect(
      layoutHintFor({ layout: templateLayout(templateByKey('ctem')), kind: 'personal' })
    ).toBeNull()
  })

  it('a widget id already taken gets a fresh one', () => {
    const layout = [
      w('w_ct1', 'exposure.priority_open'),
      w('w_ct2', 'intel.kev_open'),
      w('w_ct11', 'findings.open'),
    ]
    const hint = layoutHintFor({ layout, kind: 'personal' })!
    const next = withTemplateWidgets(layout, templateByKey('ctem'), hint.missing)
    const ids = next.map((x) => (x.config as { id: string }).id)
    expect(new Set(ids).size).toBe(ids.length)
    expect(ids).toContain('w_ct11_2')
  })

  it('organization dashboards and non-template layouts get no hint', () => {
    const tpl = templateLayout(templateByKey('ctem')).slice(0, 4)
    expect(layoutHintFor({ layout: tpl, kind: 'organization' })).toBeNull()
    expect(layoutHintFor({ layout: [w('a', 'findings.open')], kind: 'personal' })).toBeNull()
  })

  it('a full copy in the earlier order or sizes is offered the new arrangement, nothing to add', () => {
    for (const key of ['ctem', 'executive', 'surface', 'program', 'triage'] as const) {
      const tpl = templateLayout(templateByKey(key))
      const moved = [tpl[2], ...tpl.slice(0, 2), ...tpl.slice(3)]
      expect(layoutHintFor({ layout: moved, kind: 'personal' })).toMatchObject({
        template: key,
        missing: [],
        rearranged: true,
      })
      const resized = tpl.map((x, i) => (i === 0 ? { ...x, h: x.h + 1 } : x))
      expect(layoutHintFor({ layout: resized, kind: 'personal' })?.rearranged).toBe(true)
    }
  })

  it("a widget of the person's own between template widgets is not a rearrangement", () => {
    const tpl = templateLayout(templateByKey('ctem'))
    const own = w('mine1', 'crown_jewels.exposed')
    expect(
      layoutHintFor({ layout: [...tpl.slice(0, 2), own, ...tpl.slice(2)], kind: 'personal' })
    ).toBeNull()
  })
})
