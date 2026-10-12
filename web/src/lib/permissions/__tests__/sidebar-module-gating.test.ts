/**
 * Sidebar rows follow the organization's modules through the real access
 * checks. A beta module switched off used to stay in the sidebar (the beta
 * check returned before the enabled check), leading to a page the route guard
 * then refused.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import { sidebarData } from '@/config/sidebar-data'
import { useFilteredSidebarData } from '@/lib/permissions/use-filtered-sidebar'

let moduleIds: string[] = []
const modules = [
  { id: 'attack_simulation', slug: 'attack-simulation', is_active: true, release_status: 'beta' },
  { id: 'suppressions', slug: 'suppressions', is_active: true, release_status: 'released' },
]

vi.mock('next/navigation', () => ({ usePathname: () => '/' }))
vi.mock('@/context/bootstrap-provider', () => ({
  useBootstrapModules: () => ({ moduleIds, modules }),
}))
vi.mock('@/lib/permissions/hooks', () => ({
  usePermissions: () => ({
    can: () => true,
    canAny: () => true,
    isRole: () => false,
    isAnyRole: () => false,
    tenantRole: 'member',
  }),
}))

function titles(): string[] {
  const { result } = renderHook(() => useFilteredSidebarData(sidebarData))
  const out: string[] = []
  for (const g of result.current.data.navGroups) {
    for (const i of g.items) out.push(i.title)
  }
  return out
}

describe('sidebar module gating', () => {
  beforeEach(() => {
    moduleIds = ['dashboard', 'findings', 'attack_simulation', 'suppressions']
  })

  it('shows a beta module that is on', () => {
    expect(titles()).toContain('Attack simulation')
  })

  it('hides a beta module that is off', () => {
    moduleIds = moduleIds.filter((m) => m !== 'attack_simulation')
    expect(titles()).not.toContain('Attack simulation')
  })

  it('Exceptions follows the suppressions module, as its API does', () => {
    expect(titles()).toContain('Exceptions')
    moduleIds = moduleIds.filter((m) => m !== 'suppressions')
    expect(titles()).not.toContain('Exceptions')
  })
})
