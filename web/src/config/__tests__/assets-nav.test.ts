/**
 * Discovery > Assets is one row with route tabs Inventory | Groups | What
 * changed | Suggestions (docs/ui/scoping-ia-2026-10.md, C8). The retired
 * /attack-surface/internal and /cloud pages redirect to the inventory with the
 * filter they applied (D5). Every tab lives under /assets (/assets/groups,
 * /assets/suggestions): a URL mirrors its place in the nav (RFC-042 §6.3.6,
 * §6.19). The APIs stay /api/v1/asset-groups and /api/v1/relationships.
 */
import { describe, expect, it } from 'vitest'
import { existsSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { sidebarData } from '../sidebar-data'
import { ASSETS_SECTION_TABS } from '../section-tabs'
import { matchRoutePermission, routePermissions } from '../route-permissions'
import { Permission } from '@/lib/permissions/constants'
import { resolveLegacyRoute } from '../legacy-routes'
import { checkIsActive } from '@/components/layout/nav-active'
import { parseInventoryFilters } from '@/features/assets/lib/inventory-url'
import type { NavCollapsible, NavItem, NavLink } from '@/components/types'

const isCollapsible = (i: NavItem): i is NavCollapsible =>
  Array.isArray((i as NavCollapsible).items)
const discovery = sidebarData.navGroups.find((g) => g.title === 'Discovery')!
const rows = discovery.items.filter((i) => !isCollapsible(i)) as NavLink[]
const assets = rows.find((r) => r.title === 'Assets')!

describe('Discovery > Assets', () => {
  it('is one row carrying the tabs, with no gate of its own', () => {
    expect(assets.url).toBe('/assets')
    expect(assets.sections).toBe(ASSETS_SECTION_TABS)
    expect(assets.module).toBeUndefined()
    expect(assets.permission).toBeUndefined()
  })

  it('lists the approved tabs, in order, each under its row url', () => {
    expect(ASSETS_SECTION_TABS.map((t) => [t.label, t.href, t.module])).toEqual([
      ['Inventory', '/assets', 'assets'],
      ['Groups', '/assets/groups', 'assets'],
      ['What changed', '/assets/changes', 'assets'],
      ['Web surface', '/assets/web', 'assets'],
      ['Suggestions', '/assets/suggestions', 'relationships'],
    ])
  })

  it.each([...ASSETS_SECTION_TABS])('$label tab binds its route guard', (tab) => {
    const guard = matchRoutePermission(tab.href)
    expect(guard?.module).toBe(tab.module)
    expect(guard?.permission).toBe(tab.permission)
  })

  it('no tab is also a sidebar row', () => {
    const urls = rows.filter((r) => r !== assets).map((r) => r.url)
    for (const tab of ASSETS_SECTION_TABS) expect(urls).not.toContain(tab.href)
  })

  it('Discovery rows, in order', () => {
    expect(rows.map((r) => r.title)).toEqual([
      'Scans',
      'Sensors',
      'CI/CD',
      'Attack surface',
      'Assets',
      'Exposures',
      'Credential leaks',
      'Components',
    ])
  })

  it.each([
    '/assets',
    '/assets/repositories/abc',
    '/assets/changes',
    '/assets/groups',
    '/assets/groups/abc',
    '/assets/suggestions',
  ])('%s lights up the Assets row only', (path) => {
    const active = sidebarData.navGroups.flatMap((g) =>
      g.items.filter((i): i is NavLink => !isCollapsible(i) && checkIsActive(path, i))
    )
    expect(active).toEqual([assets])
  })
})

describe('retired attack-surface pages', () => {
  it('/attack-surface/internal opens the internal inventory', () => {
    const to = resolveLegacyRoute('/attack-surface/internal')!
    expect(to.split('?')[0]).toBe('/assets')
    const f = parseInventoryFilters(new URLSearchParams(to.split('?')[1]))
    expect(f.scopes).toEqual(['internal'])
    expect(f.types).toEqual(['host', 'database', 'network', 'container'])
  })

  it('/attack-surface/cloud opens the cloud accounts', () => {
    const to = resolveLegacyRoute('/attack-surface/cloud')!
    const f = parseInventoryFilters(new URLSearchParams(to.split('?')[1]))
    expect(f.types).toEqual(['cloud_account'])
  })

  it('/attack-surface and /attack-surface/external stay', () => {
    expect(resolveLegacyRoute('/attack-surface')).toBeNull()
    expect(resolveLegacyRoute('/attack-surface/external')).toBeNull()
    expect(matchRoutePermission('/attack-surface/external')?.module).toBe('attack_surface')
  })
})

const ASSETS_DIR = join(process.cwd(), 'src', 'app', '(dashboard)', '(discovery)', 'assets')

describe('Asset groups live under /assets/groups', () => {
  // What /asset-groups and /asset-groups/** required before the move. The new
  // URL must ask for exactly this, no more (the inventory's assets:read) and
  // no less.
  const BEFORE_MOVE = { permission: Permission.AssetGroupsRead, module: 'assets' }

  it.each(['/assets/groups', '/assets/groups/', '/assets/groups/abc', '/assets/groups/abc/edit'])(
    '%s keeps the old /asset-groups guard',
    (path) => {
      expect(matchRoutePermission(path)).toEqual(BEFORE_MOVE)
    }
  )

  it('is not loosened or tightened by the generic /assets/** rule', () => {
    expect(routePermissions['/assets/**']).toEqual({
      permission: Permission.AssetsRead,
      module: 'assets',
    })
    expect(matchRoutePermission('/assets/groups/abc')).not.toEqual(routePermissions['/assets/**'])
    // A sibling that merely starts with "groups" and an asset detail page
    // still get the inventory guard.
    expect(matchRoutePermission('/assets/groupsx')).toEqual(routePermissions['/assets/**'])
    expect(matchRoutePermission('/assets/0b9f6c3e-1111-4222-8333-944455556666')).toEqual(
      routePermissions['/assets/**']
    )
  })

  it('no route permission or tab still points at /asset-groups', () => {
    expect(Object.keys(routePermissions).filter((k) => k.startsWith('/asset-groups'))).toEqual([])
    expect(ASSETS_SECTION_TABS.map((t) => t.href)).not.toContain('/asset-groups')
  })

  it('/asset-groups has no page and no redirect (owner decision: it 404s)', () => {
    expect(existsSync(join(ASSETS_DIR, '..', '..', '(scoping)', 'asset-groups'))).toBe(false)
    expect(resolveLegacyRoute('/asset-groups')).toBeNull()
    expect(resolveLegacyRoute('/asset-groups/abc?tab=assets')).toBeNull()
  })

  // Next.js matches a static segment before a dynamic one at the same level,
  // so /assets/groups opens the groups page, not /assets/[id] with id=groups.
  // That only holds while `groups` is a static folder next to `[id]`, in the
  // same route group, with its own page and its own [id] detail page.
  it('is a static route next to /assets/[id], so it wins over the asset detail page', () => {
    const entries = readdirSync(ASSETS_DIR).filter((e) =>
      statSync(join(ASSETS_DIR, e)).isDirectory()
    )
    expect(entries).toContain('[id]')
    expect(entries).toContain('groups')
    expect(existsSync(join(ASSETS_DIR, 'groups', 'page.tsx'))).toBe(true)
    expect(existsSync(join(ASSETS_DIR, 'groups', '[id]', 'page.tsx'))).toBe(true)
    // No catch-all at /assets that could shadow it.
    expect(entries.filter((e) => e.startsWith('[...') || e.startsWith('[[...'))).toEqual([])
  })

  // Reserved /assets/* page segments: no asset type, class or lens may take
  // these names (api/cmd/gen-asset-types rejects them; RFC-042 §6.3.6).
  it.each(['changes', 'duplicates', 'groups', 'suggestions', 'web'])(
    '/assets/%s is a reserved static page',
    (segment) => {
      expect(existsSync(join(ASSETS_DIR, segment, 'page.tsx'))).toBe(true)
    }
  )
})

describe('Relationship suggestions live under /assets/suggestions', () => {
  // What /relationships/suggestions (via /relationships/**) required before
  // the move: the inventory permission, gated on the relationships module.
  const BEFORE_MOVE = { permission: Permission.AssetsRead, module: 'relationships' }

  it.each(['/assets/suggestions', '/assets/suggestions/', '/assets/suggestions/abc'])(
    '%s keeps the old /relationships/** guard',
    (path) => {
      expect(matchRoutePermission(path)).toEqual(BEFORE_MOVE)
    }
  )

  it('the generic /assets/** rule does not override the module gate', () => {
    // /assets/** is gated on `assets`; if it won, turning `relationships` off
    // would leave the Suggestions page reachable.
    expect(routePermissions['/assets/**'].module).toBe('assets')
    expect(matchRoutePermission('/assets/suggestions')?.module).toBe('relationships')
    expect(matchRoutePermission('/assets/suggestionsx')).toEqual(routePermissions['/assets/**'])
  })

  it('no route permission or tab still points at /relationships', () => {
    expect(Object.keys(routePermissions).filter((k) => k.startsWith('/relationships'))).toEqual([])
    expect(ASSETS_SECTION_TABS.map((t) => t.href)).not.toContain('/relationships/suggestions')
  })

  it('/relationships/suggestions has no page and no redirect (owner decision: it 404s)', () => {
    expect(existsSync(join(ASSETS_DIR, '..', 'relationships'))).toBe(false)
    expect(existsSync(join(ASSETS_DIR, 'suggestions', 'page.tsx'))).toBe(true)
    expect(resolveLegacyRoute('/relationships/suggestions')).toBeNull()
  })
})
