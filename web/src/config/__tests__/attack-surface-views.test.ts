/**
 * The attack surface has five views (research/353 D1). Every route tab of the
 * section belongs to exactly one view, so a new tab cannot slip in as a sixth
 * strip entry: it has to be placed in a view (and then shows in its lens).
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import { ATTACK_SURFACE_SECTION_TABS } from '../section-tabs'
import { ATTACK_SURFACE_VIEWS, viewOfRoute } from '../attack-surface-views'

describe('attack surface views', () => {
  it('are the five jobs, in order', () => {
    expect(ATTACK_SURFACE_VIEWS.map((v) => v.id)).toEqual([
      'overview',
      'inventory',
      'exposures',
      'changes',
      'discovery',
    ])
  })

  it('place every section tab in exactly one view', () => {
    const owners = new Map<string, string[]>()
    for (const v of ATTACK_SURFACE_VIEWS)
      for (const r of v.routes) owners.set(r.href, [...(owners.get(r.href) ?? []), v.id])
    const misplaced = ATTACK_SURFACE_SECTION_TABS.filter(
      (tab) => (owners.get(tab.href)?.length ?? 0) !== 1
    ).map((tab) => tab.href)
    expect(misplaced).toEqual([])
    for (const [href, ids] of owners) expect(ids, href).toHaveLength(1)
  })

  it('give every view and relabelled route an i18n key', () => {
    for (const v of ATTACK_SURFACE_VIEWS) {
      expect(v.labelKey).toMatch(/^attackSurface\.view\./)
      for (const r of v.routes) if (r.label) expect(r.labelKey, r.href).toBeTruthy()
    }
  })

  it('find the view of a route, nested pages included', () => {
    expect(viewOfRoute('/attack-surface').id).toBe('overview')
    expect(viewOfRoute('/attack-surface/posture').id).toBe('overview')
    expect(viewOfRoute('/attack-surface/technologies').id).toBe('inventory')
    expect(viewOfRoute('/attack-surface/certificates').id).toBe('inventory')
    expect(viewOfRoute('/attack-surface/web').id).toBe('inventory')
    expect(viewOfRoute('/attack-surface/exposures').id).toBe('exposures')
    expect(viewOfRoute('/attack-surface/lookalikes').id).toBe('exposures')
    expect(viewOfRoute('/attack-surface/changes').id).toBe('changes')
    expect(viewOfRoute('/attack-surface/pages').id).toBe('changes')
    expect(viewOfRoute('/attack-surface/discovery').id).toBe('discovery')
    expect(viewOfRoute('/attack-surface/review').id).toBe('discovery')
    expect(viewOfRoute('/attack-surface/review/anything').id).toBe('discovery')
    expect(viewOfRoute('/attack-surface/unknown').id).toBe('overview')
  })
})

/**
 * One navigation for the section: every attack-surface page renders the
 * shared AttackSurfaceSectionTabs (which draws the views and the lens) and
 * never a strip or tab list of its own.
 */
describe('attack surface pages', () => {
  const ROOT = join(__dirname, '../../app/(dashboard)/(scoping)/attack-surface')
  function* pages(dir: string): Generator<string> {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name)
      if (statSync(p).isDirectory()) yield* pages(p)
      else if (name === 'page.tsx') yield p
    }
  }

  // A page that renders a feature view: the view draws the navigation.
  const DELEGATES: Record<string, string> = {
    'web/page.tsx': '../../features/web-surface/components/web-surface-view.tsx',
  }
  // Pages outside the five views, to be retired (research/353 D9). Never add one.
  const ORPHANS = new Set(['external/page.tsx'])

  it('use the shared section navigation', () => {
    const offenders: string[] = []
    for (const file of pages(ROOT)) {
      const rel = relative(ROOT, file)
      if (ORPHANS.has(rel)) continue
      const src = DELEGATES[rel]
        ? readFileSync(join(__dirname, DELEGATES[rel]), 'utf8')
        : readFileSync(file, 'utf8')
      if (/<(Gated)?SectionTabs\b|<TabsList\b/.test(src)) offenders.push(`${rel}: own tabs`)
      if (!/<AttackSurfaceSectionTabs\b/.test(src))
        offenders.push(`${rel}: no AttackSurfaceSectionTabs`)
    }
    expect(offenders).toEqual([])
  })
})
