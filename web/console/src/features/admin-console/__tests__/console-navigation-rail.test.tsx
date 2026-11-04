import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { SidebarProvider } from '@/components/ui/sidebar'
import { AdminConsoleSidebar } from '../components/admin-console-sidebar'
import { actingRoleLabel, type AdminIdentity } from '../types'

let pathname = '/'
vi.mock('next/navigation', () => ({
  usePathname: () => pathname,
  useRouter: () => ({ push: vi.fn(), prefetch: vi.fn() }),
}))
vi.mock('@console/lib/admin-api/client', () => ({ adminFetch: vi.fn() }))

const owner: AdminIdentity = {
  id: 'a',
  email: 'root@example.test',
  name: 'Root',
  role: 'readonly',
  max_role: 'super_admin',
  roles: ['platform_owner'],
  permissions: ['platform.console.read'],
  max_permissions: ['platform.console.read', 'platform.settings.write'],
}

function renderSidebar(admin: AdminIdentity = owner) {
  return render(
    <SidebarProvider>
      <AdminConsoleSidebar admin={admin} onSignOut={() => {}} />
    </SidebarProvider>
  )
}

describe('console sidebar and settings rail', () => {
  beforeEach(() => {
    pathname = '/'
    sessionStorage.clear()
  })

  it('shows the main groups and one Settings entry, not every setting', () => {
    renderSidebar()
    const nav = screen.getByRole('navigation', { name: 'Console navigation' })
    expect(within(nav).getByRole('link', { name: 'Settings' })).toHaveAttribute(
      'href',
      '/system/configuration'
    )
    expect(within(nav).queryByRole('link', { name: 'E-mail' })).not.toBeInTheDocument()
    expect(within(nav).getByRole('link', { name: 'Admin activity' })).toBeInTheDocument()
  })

  it('swaps to the settings rail on a settings page, with a way back', () => {
    sessionStorage.setItem('openctem.admin.settings-return-to', '/organizations?owner=none')
    pathname = '/system/email'
    renderSidebar()
    const nav = screen.getByRole('navigation', { name: 'Settings' })
    expect(within(nav).getByRole('link', { name: 'Back to console' })).toHaveAttribute(
      'href',
      '/organizations?owner=none'
    )
    expect(within(nav).getByRole('link', { name: 'E-mail' })).toHaveAttribute(
      'aria-current',
      'page'
    )
    expect(within(nav).queryByRole('link', { name: 'Organizations' })).not.toBeInTheDocument()
  })

  it('never sends "Back to console" to another site', () => {
    sessionStorage.setItem('openctem.admin.settings-return-to', '//evil.example/x')
    pathname = '/system/legal'
    renderSidebar()
    expect(screen.getByRole('link', { name: 'Back to console' })).toHaveAttribute('href', '/')
  })

  it('names what the session acts as in platform role words', () => {
    renderSidebar()
    expect(screen.getAllByText('Read-only until you elevate').length).toBeGreaterThan(0)
    expect(screen.queryByText('Read-only admin')).not.toBeInTheDocument()
  })
})

describe('actingRoleLabel', () => {
  it('uses the role the session is elevated as', () => {
    expect(
      actingRoleLabel({
        ...owner,
        role: 'super_admin',
        elevated_until: '2099-01-01T00:00:00Z',
        elevated_as: 'platform_owner',
        permissions: owner.max_permissions,
      })
    ).toEqual({ key: 'admin.platformRole.platform_owner', fallback: 'platform_owner' })
  })

  it('says read-only while an elevation would add something', () => {
    expect(actingRoleLabel(owner).key).toBe('admin.shell.actingReadOnly')
  })

  it('names the held role when the installation does not ask for elevation', () => {
    expect(
      actingRoleLabel({ ...owner, role: 'super_admin', permissions: owner.max_permissions }).key
    ).toBe('admin.platformRole.platform_owner')
  })
})
