import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { resetAdminCredentials, updateAdminUser, useAdminUsers } from '../api/use-admin-users'
import {
  assignPlatformRole,
  revokePlatformRole,
  usePlatformRoleAssignments,
  usePlatformRoles,
} from '../api/use-platform-roles'
import type {
  AdminIdentity,
  AdminUserRecord,
  PlatformRoleAssignment,
  PlatformRoleInfo,
} from '../types'
import AdministratorsPage from '@console/app/(console)/security/administrators/page'
import RolesPage from '@console/app/(console)/security/roles/page'

const mocks = vi.hoisted(() => ({ admin: { current: null as AdminIdentity | null } }))

vi.mock('../components/admin-console-shell', () => ({
  useAdmin: () => mocks.admin.current,
  useAdminOrNull: () => mocks.admin.current,
}))
vi.mock('../api/use-admin-users', () => ({
  useAdminUsers: vi.fn(),
  updateAdminUser: vi.fn(),
  resetAdminCredentials: vi.fn(),
  confirmBreakGlassTest: vi.fn(),
  unbindAdminIdP: vi.fn(),
  provisionAdministrator: vi.fn(),
}))
vi.mock('../api/use-platform-roles', () => ({
  usePlatformRoles: vi.fn(),
  usePlatformRoleAssignments: vi.fn(),
  assignPlatformRole: vi.fn(),
  revokePlatformRole: vi.fn(),
}))
vi.mock('../components/create-admin-dialog', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../components/create-admin-dialog')>()),
  CreateAdminDialog: () => <button type="button">Create administrator</button>,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('next/navigation', () => ({
  usePathname: () => '/security/administrators',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function swr<T>(data: T | undefined, error?: unknown) {
  return { data, error, isLoading: false, isValidating: false, mutate: vi.fn() } as never
}

function adminRecord(patch: Partial<AdminUserRecord>): AdminUserRecord {
  return {
    id: 'a2',
    email: 'ops@op.test',
    name: 'Ops',
    role: 'ops_admin',
    is_active: true,
    last_used_at: '2026-10-08T09:00:00Z',
    created_at: '2026-10-01T08:00:00Z',
    updated_at: '2026-10-01T08:00:00Z',
    is_break_glass: false,
    break_glass_test_overdue: false,
    password_change_required: false,
    idp_bound: false,
    ...patch,
  }
}

const me = (role: AdminIdentity['role']) => {
  mocks.admin.current = { id: 'a1', email: 'me@op.test', name: 'Me', role }
}

describe('Administrators page', () => {
  beforeEach(() => vi.clearAllMocks())

  it('is for super admins only (no request otherwise)', () => {
    vi.mocked(useAdminUsers).mockReturnValue(swr(undefined))
    me('ops_admin')
    render(<AdministratorsPage />)
    expect(useAdminUsers).toHaveBeenCalledWith(1, false)
    expect(screen.getByText(/platform roles do not include this/i)).toBeInTheDocument()
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('lists administrators with the count once, named columns and a menu on other rows only', async () => {
    vi.mocked(useAdminUsers).mockReturnValue(
      swr({
        data: [
          adminRecord({ id: 'a1', email: 'me@op.test', name: 'Me', role: 'super_admin' }),
          adminRecord({}),
          adminRecord({
            id: 'a3',
            email: 'bg@op.test',
            name: 'Break glass',
            role: 'super_admin',
            is_break_glass: true,
            break_glass_test_overdue: true,
          }),
        ],
        total: 3,
        page: 1,
        per_page: 50,
        total_pages: 1,
      })
    )
    me('super_admin')
    render(<AdministratorsPage />)

    expect(document.querySelectorAll('[data-slot="list-count"]')).toHaveLength(1)
    const table = screen.getByRole('table', { name: 'Administrators' })
    for (const h of ['Administrator', 'Role', 'Sign-in', 'Last tested', 'Status', 'Last active'])
      expect(within(table).getByRole('columnheader', { name: new RegExp(h) })).toBeInTheDocument()
    expect(screen.getAllByText('Test overdue').length).toBeGreaterThan(0)
    // The name keeps its room; the address gives way first.
    expect(within(table).getByText('Break glass')).toHaveClass('shrink-0', 'max-w-[60%]')
    expect(within(table).getByText('bg@op.test')).toHaveClass('min-w-0', 'truncate')

    // Your own row has no menu; the others are named by the address.
    const menus = screen.getAllByRole('button', { name: /^Actions for the administrator/ })
    expect(menus).toHaveLength(2)
    expect(screen.queryByRole('button', { name: /me@op\.test/ })).toBeNull()

    // A destructive item opens the same confirmation; nothing is sent before it.
    const user = userEvent.setup()
    await user.click(
      screen.getByRole('button', { name: 'Actions for the administrator ops@op.test' })
    )
    const items = await screen.findAllByRole('menuitem')
    expect(items.map((i) => i.textContent)).toContain('Reset two-step verification')
    expect(items.map((i) => i.textContent)).toContain('Deactivate')
    await user.click(items.find((i) => i.textContent === 'Deactivate')!)
    expect(updateAdminUser).not.toHaveBeenCalled()
    // A roster change asks a reason (with an example for this very action) and
    // a fresh code; nothing is sent until both are there.
    const dialog = await screen.findByRole('dialog')
    expect(
      within(dialog).getByText(/Deactivate the administrator ops@op\.test/)
    ).toBeInTheDocument()
    const reason = within(dialog).getByLabelText(/^Reason/)
    expect(reason).toHaveAttribute('placeholder', 'Left the operations team, ticket 2231')
    const deactivate = within(dialog).getByRole('button', { name: 'Deactivate' })
    expect(deactivate).toBeDisabled()
    await user.type(reason, 'Left the company, ticket 77')
    await user.type(within(dialog).getByLabelText('Code from your authenticator app'), '123456')
    await user.click(deactivate)
    await waitFor(() =>
      expect(updateAdminUser).toHaveBeenCalledWith(
        'a2',
        { is_active: false },
        { reason: 'Left the company, ticket 77', totp_code: '123456' }
      )
    )
    expect(resetAdminCredentials).not.toHaveBeenCalled()
  })

  it('shows the load error in the table with Retry', () => {
    vi.mocked(useAdminUsers).mockReturnValue(swr(undefined, new Error('boom')))
    me('super_admin')
    render(<AdministratorsPage />)
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })
})

const ROLES: PlatformRoleInfo[] = [
  {
    key: 'super_admin',
    name: 'Platform owner',
    description: 'Everything',
    base: true,
    tier: 'super_admin',
    permissions: ['a', 'b'],
    holders: 1,
  },
  {
    key: 'auditor',
    name: 'Auditor',
    description: 'Reads the audit log',
    base: false,
    tier: 'viewer' as PlatformRoleInfo['tier'],
    permissions: ['c'],
    holders: 0,
  },
]

function holder(patch: Partial<PlatformRoleAssignment>): PlatformRoleAssignment {
  return {
    admin_id: 'a2',
    email: 'ops@op.test',
    name: 'Ops',
    active: true,
    break_glass: false,
    roles: ['ops_admin', 'auditor'],
    ...patch,
  }
}

describe('Roles page', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the roles to everyone and the holders only with platform.admins.read', () => {
    vi.mocked(usePlatformRoles).mockReturnValue(swr({ roles: ROLES, owners_warning: false }))
    vi.mocked(usePlatformRoleAssignments).mockReturnValue(swr(undefined))
    me('ops_admin')
    render(<RolesPage />)
    expect(usePlatformRoleAssignments).toHaveBeenCalledWith(false)
    expect(screen.getByRole('table', { name: 'Platform roles' })).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: 'Who holds them' })).toBeNull()
    expect(document.querySelectorAll('[data-slot="list-count"]')).toHaveLength(1)
  })

  it('gives a role from the row menu and takes one from its badge, never on yourself', async () => {
    vi.mocked(usePlatformRoles).mockReturnValue(swr({ roles: ROLES, owners_warning: true }))
    vi.mocked(usePlatformRoleAssignments).mockReturnValue(
      swr({
        data: [holder({ admin_id: 'a1', email: 'me@op.test', name: 'Me' }), holder({})],
      })
    )
    me('super_admin')
    render(<RolesPage />)
    expect(screen.getByText('Fewer than two platform owners')).toBeInTheDocument()
    expect(document.querySelectorAll('[data-slot="list-count"]')).toHaveLength(2)

    // One "Take" button (the other holder's additional role). The one row
    // action is the button itself, never a menu of one item.
    expect(screen.getAllByRole('button', { name: /^Take / })).toHaveLength(1)
    expect(screen.queryByRole('button', { name: /^Actions for the administrator/ })).toBeNull()
    const give = screen.getAllByRole('button', { name: 'Give a role' })
    expect(give).toHaveLength(1)

    const user = userEvent.setup()
    await user.click(give[0])
    expect(assignPlatformRole).not.toHaveBeenCalled()
    expect(await screen.findByText('Give a platform role')).toBeInTheDocument()
    expect(revokePlatformRole).not.toHaveBeenCalled()
  })
})
