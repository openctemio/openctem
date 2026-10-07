/**
 * Discovery > Scans is one row with route tabs Scans | Runs | Workflows
 * (research/60 N2): one table per route, so each list keeps plain page,
 * per_page and sort parameters. Scan workflows left Mobilization; event
 * automation is Mobilization > Automations. The old /pipelines and /workflows
 * pages are gone with no redirect (owner rule: no aliases).
 */
import { describe, expect, it } from 'vitest'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { sidebarData } from '../sidebar-data'
import { SCANS_SECTION_TABS } from '../section-tabs'
import { matchRoutePermission } from '../route-permissions'
import { Permission } from '@/lib/permissions/constants'
import { resolveLegacyRoute } from '../legacy-routes'
import { checkIsActive } from '@/components/layout/nav-active'
import type { NavCollapsible, NavItem, NavLink } from '@/components/types'

const isCollapsible = (i: NavItem): i is NavCollapsible =>
  Array.isArray((i as NavCollapsible).items)
const links = sidebarData.navGroups.flatMap((g) =>
  g.items.filter((i): i is NavLink => !isCollapsible(i))
)
const scans = links.find((r) => r.title === 'Scans')!
const APP = join(__dirname, '..', '..', 'app', '(dashboard)')

describe('Discovery > Scans', () => {
  it('is one row carrying the tabs', () => {
    expect(scans.url).toBe('/scans')
    expect(scans.sections).toBe(SCANS_SECTION_TABS)
  })

  it('lists Scans, Runs and Workflows under /scans', () => {
    expect(SCANS_SECTION_TABS.map((t) => [t.label, t.href, t.module])).toEqual([
      ['Scans', '/scans', 'scans'],
      ['Runs', '/scans/runs', 'scans'],
      ['Workflows', '/scans/workflows', 'scan_workflows'],
    ])
  })

  it.each([...SCANS_SECTION_TABS])('$label tab binds its route guard', (tab) => {
    const guard = matchRoutePermission(tab.href)
    expect(guard?.module).toBe(tab.module)
    expect(guard?.permission).toBe(tab.permission)
  })

  it('runs need scans:read; workflows need the workflow permission', () => {
    expect(matchRoutePermission('/scans/runs')?.permission).toBe(Permission.ScansRead)
    expect(matchRoutePermission('/scans/workflows/abc')?.permission).toBe(
      Permission.ScanWorkflowsRead
    )
    expect(matchRoutePermission('/scans/workflows/abc')?.module).toBe('scan_workflows')
  })

  it.each(['/scans', '/scans/runs', '/scans/workflows', '/scans/workflows/abc'])(
    '%s lights up the Scans row only',
    (path) => {
      expect(links.filter((i) => checkIsActive(path, i))).toEqual([scans])
    }
  )

  it('keeps the older names searchable in the command palette', () => {
    const workflows = SCANS_SECTION_TABS.find((t) => t.href === '/scans/workflows')!
    expect(workflows.keywords).toEqual(expect.arrayContaining(['pipeline', 'builder']))
  })

  it('has the pages for every tab and the workflow editor', () => {
    for (const page of [
      '(discovery)/scans/page.tsx',
      '(discovery)/scans/runs/page.tsx',
      '(discovery)/scans/workflows/page.tsx',
      '(discovery)/scans/workflows/[id]/page.tsx',
    ]) {
      expect(existsSync(join(APP, page)), page).toBe(true)
    }
  })
})

describe('Mobilization > Automations', () => {
  it('is the event-rule page at /automations', () => {
    const row = links.find((r) => r.title === 'Automations')!
    expect(row.url).toBe('/automations')
    expect(matchRoutePermission('/automations')?.permission).toBe(Permission.WorkflowsRead)
    expect(existsSync(join(APP, '(mobilization)/automations/page.tsx'))).toBe(true)
  })

  it('no sidebar row is named Workflows or Scan Pipelines any more', () => {
    const titles = links.map((l) => l.title)
    expect(titles).not.toContain('Workflows')
    expect(titles).not.toContain('Scan Pipelines')
  })
})

describe('old routes', () => {
  it.each(['/pipelines', '/pipelines/abc/builder', '/workflows', '/scans?tab=runs'])(
    '%s has no page, no guard and no redirect',
    (path) => {
      const bare = path.split('?')[0]
      expect(resolveLegacyRoute(bare)).toBeNull()
      if (bare !== '/scans') expect(matchRoutePermission(bare)).toBeUndefined()
    }
  )

  it('the old page files are gone', () => {
    for (const page of [
      '(mobilization)/pipelines/page.tsx',
      '(mobilization)/pipelines/[id]/builder/page.tsx',
      '(mobilization)/workflows/page.tsx',
    ]) {
      expect(existsSync(join(APP, page)), page).toBe(false)
    }
  })
})
