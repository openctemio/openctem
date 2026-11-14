import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SidebarProvider } from '@/components/ui/sidebar'
import { adminNav } from '../config/admin-nav'
import { consoleCrumbLevels } from '../lib/console-crumbs'
import { visibleAdminNav } from '../lib/admin-nav-visibility'
import type { AdminIdentity } from '../types'

let pathname = '/'
vi.mock('next/navigation', () => ({
  usePathname: () => pathname,
  useRouter: () => ({ push: vi.fn(), prefetch: vi.fn() }),
}))
vi.mock('@console/lib/admin-api/client', () => ({ adminFetch: vi.fn() }))

const { AdminConsoleSidebar } = await import('../components/admin-console-sidebar')

const label = (i: { title: string }) => i.title
const record = (url: string) => `record of ${url}`

const readonlyAdmin: AdminIdentity = {
  id: 'a',
  email: 'ro@example.test',
  name: 'Read Only',
  role: 'readonly',
  roles: [],
  permissions: ['platform.console.read'],
}

describe('console breadcrumb levels (shell package 0.4)', () => {
  it('names a navigation page as the sidebar does, one level, linked', () => {
    const org = adminNav.flatMap((s) => s.items).find((i) => i.url === '/organizations')!
    expect(consoleCrumbLevels('/organizations', adminNav, label, record)).toEqual([
      { path: '/organizations', label: org.title, hasPage: true },
    ])
  })

  it('adds the record kind as the current level under its list page', () => {
    const levels = consoleCrumbLevels(
      '/organizations/7b0d3c1e-1111-4222-8333-944445555666',
      adminNav,
      label,
      record
    )
    expect(levels.map((l) => l.label)).toEqual(['Organizations', 'record of /organizations'])
    expect(levels[0].path).toBe('/organizations')
  })

  it('takes the deepest navigation entry (Sign-ups, not Access requests)', () => {
    const levels = consoleCrumbLevels('/requests/sign-ups', adminNav, label, record)
    expect(levels).toHaveLength(1)
    expect(levels[0].path).toBe('/requests/sign-ups')
  })

  it('shows no level on the overview or on a page the navigation does not list', () => {
    expect(consoleCrumbLevels('/', adminNav, label, record)).toEqual([])
    expect(consoleCrumbLevels('/about/licenses', adminNav, label, record)).toEqual([])
  })

  it('never names a page the administrator cannot see', () => {
    const visible = visibleAdminNav(readonlyAdmin)
    const hidden = adminNav
      .flatMap((s) => s.items)
      .filter((i) => !visible.flatMap((s) => s.items).some((v) => v.url === i.url))
    expect(hidden.length).toBeGreaterThan(0)
    for (const item of hidden) {
      const levels = consoleCrumbLevels(item.url, visible, label, record)
      expect(
        levels.map((l) => l.label),
        item.url
      ).not.toContain(item.title)
    }
  })
})

describe('console sidebar header (shell package 0.3)', () => {
  it('shows the Admin chip in the brand row and the context row with the acting role', () => {
    pathname = '/'
    render(
      <SidebarProvider>
        <AdminConsoleSidebar admin={readonlyAdmin} onSignOut={() => {}} />
      </SidebarProvider>
    )
    expect(screen.getByText('Admin')).toHaveAttribute('data-slot', 'badge')
    expect(screen.getAllByText('Platform administration').length).toBeGreaterThan(0)
  })
})
