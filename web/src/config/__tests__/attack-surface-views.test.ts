/**
 * One tab row for Discovery > Attack surface (owner rule 2026-11-24: one tab
 * level per screen). Every section tab is either in the row or a page opened
 * from another page, so a new tab cannot slip in unplaced, and none of them is
 * drawn as a second row under the strip.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import { ATTACK_SURFACE_SECTION_TABS } from '../section-tabs'
import { ATTACK_SURFACE_DETAIL_PAGES, ATTACK_SURFACE_TAB_ORDER } from '../attack-surface-views'

describe('attack surface tab row', () => {
  it('places every section tab once: in the row or as a page opened from another', () => {
    const placed = [...ATTACK_SURFACE_TAB_ORDER, ...ATTACK_SURFACE_DETAIL_PAGES]
    expect(new Set(placed).size).toBe(placed.length)
    expect([...placed].sort()).toEqual(ATTACK_SURFACE_SECTION_TABS.map((t) => t.href).sort())
  })

  it('opens on the Overview, and Posture is not a tab', () => {
    expect(ATTACK_SURFACE_TAB_ORDER[0]).toBe('/attack-surface')
    expect(ATTACK_SURFACE_TAB_ORDER).not.toContain('/attack-surface/posture')
  })
})

/**
 * One navigation for the section: every attack-surface page renders the
 * shared AttackSurfaceSectionTabs (the one tab row) and
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
    'discovery/page.tsx': '../../features/attack-surface/components/easm-discovery.tsx',
  }
  // Pages outside the tab row, to be retired (research/353 D9). Never add one.
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
      if (/<SegmentedLens\b|part="lens"/.test(src)) offenders.push(`${rel}: a second tab level`)
    }
    expect(offenders).toEqual([])
  })
})
