/**
 * Tabs gated by module, end to end through the real access checks: the page's
 * tab strip (GatedSectionTabs) and the sidebar row (useFilteredSidebarData)
 * make the same decision for the same module list.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, renderHook, screen } from '@testing-library/react'
import { GatedSectionTabs } from '../gated-section-tabs'
import { BUSINESS_CONTEXT_SECTION_TABS } from '@/config/section-tabs'
import { sidebarData } from '@/config/sidebar-data'
import { useFilteredSidebarData } from '@/lib/permissions/use-filtered-sidebar'
import type { NavLink } from '@/components/types'

let pathname = '/business-services'
let moduleIds: string[] = []
let perms: string[] = []

vi.mock('next/navigation', () => ({ usePathname: () => pathname }))
vi.mock('@/context/bootstrap-provider', () => ({
  useBootstrapModules: () => ({ moduleIds, modules: [] }),
}))
vi.mock('@/lib/permissions/hooks', () => ({
  usePermissions: () => ({
    can: (p: string) => perms.includes(p),
    canAny: (...p: string[]) => p.some((x) => perms.includes(x)),
    isRole: () => false,
    isAnyRole: () => false,
    tenantRole: 'member',
  }),
}))

const ALL_PERMS = ['assets:read', 'ctem:business_services:read', 'ctem:cycles:read', 'scope:read']

function scopingRow(title: string): NavLink | undefined {
  const { result } = renderHook(() => useFilteredSidebarData(sidebarData))
  const scoping = result.current.data.navGroups.find((g) => g.title === 'Scoping')
  return scoping?.items.find((i) => i.title === title) as NavLink | undefined
}

describe('GatedSectionTabs', () => {
  beforeEach(() => {
    pathname = '/business-services'
    moduleIds = ['business_services', 'business_units']
    perms = ALL_PERMS
  })

  it('shows every tab whose module is on', () => {
    render(<GatedSectionTabs tabs={BUSINESS_CONTEXT_SECTION_TABS} label="Business context" />)
    expect(screen.getAllByRole('link').map((a) => a.textContent)).toEqual([
      'Crown jewels',
      'Services',
      'Units',
    ])
    expect(screen.getByRole('link', { name: 'Services' })).toHaveAttribute('aria-current', 'page')
  })

  it('hides a tab whose module is off; crown jewels needs no module', () => {
    moduleIds = ['business_units']
    render(<GatedSectionTabs tabs={BUSINESS_CONTEXT_SECTION_TABS} />)
    expect(screen.queryByRole('link', { name: 'Services' })).toBeNull()
    expect(screen.getAllByRole('link').map((a) => a.textContent)).toEqual(['Crown jewels', 'Units'])
  })

  it('hides a tab the user lacks the permission for', () => {
    perms = ['assets:read']
    render(<GatedSectionTabs tabs={BUSINESS_CONTEXT_SECTION_TABS} />)
    expect(screen.queryByRole('link', { name: 'Services' })).toBeNull()
  })

  it('draws no strip when one tab is left', () => {
    moduleIds = ['ctem_cycles']
    const { container } = render(<GatedSectionTabs tabs={BUSINESS_CONTEXT_SECTION_TABS} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('sidebar row with gated tabs', () => {
  beforeEach(() => {
    moduleIds = ['business_services', 'business_units', 'ctem_cycles']
    perms = ALL_PERMS
  })

  it('keeps every tab and its own url when all modules are on', () => {
    const r = scopingRow('Business context')
    expect(r?.url).toBe('/crown-jewels')
    expect(r?.sections?.map((s) => s.label)).toEqual(['Crown jewels', 'Services', 'Units'])
  })

  it('keeps its own url and drops the tabs whose module is off', () => {
    moduleIds = ['business_units']
    const r = scopingRow('Business context')
    expect(r?.url).toBe('/crown-jewels')
    // The command palette reads the filtered sections: no hidden tab in search.
    expect(r?.sections?.map((s) => s.label)).toEqual(['Crown jewels', 'Units'])
  })

  it('hides the row when no tab is left', () => {
    perms = ['ctem:cycles:read']
    expect(scopingRow('Business context')).toBeUndefined()
    expect(scopingRow('Cycles')).toBeDefined()
  })

  it('the Scoping header links to the Overview only while that row is visible', () => {
    const scopingGroup = () =>
      renderHook(() => useFilteredSidebarData(sidebarData)).result.current.data.navGroups.find(
        (g) => g.title === 'Scoping'
      )
    expect(scopingGroup()?.url).toBe('/scoping')
    perms = ['ctem:cycles:read']
    expect(scopingGroup()?.url).toBeUndefined()
  })

  it('the Cycles row follows the ctem_cycles module', () => {
    moduleIds = ['business_units']
    expect(scopingRow('Cycles')).toBeUndefined()
  })
})
