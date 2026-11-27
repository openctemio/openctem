/**
 * The roles list (boards P4-Settings-Roles, -DialogsAccess): Add filter
 * narrows by role type and risk through the URL and shows each as a chip;
 * a list narrowed to custom roles with none says the four system roles always
 * exist; a system role offers no edit or delete; delete names how many members
 * hold the role; a reader without the create permission is told the page is
 * view only; a failed read says so with Retry instead of an empty list.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { I18nProvider } from '@/context/i18n-provider'
import type { Role } from '@/features/access-control'
import RolesPage from '../page'

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 'acme', role: 'owner' } }),
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/settings/roles',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))

let canMutate = true
vi.mock('@/lib/permissions', async (orig) => {
  const mod = await orig<typeof import('@/lib/permissions')>()
  const all = Object.values(mod.Permission) as string[]
  return {
    ...mod,
    Can: ({ children }: { children: ReactNode }) => (canMutate ? <>{children}</> : null),
    useHasPermission: () => canMutate,
    useCanMutate: () => canMutate,
    usePermissions: () => ({
      permissions: canMutate ? all : [],
      can: () => canMutate,
      isLoading: false,
      tenantRole: canMutate ? 'owner' : 'viewer',
    }),
  }
})

const role = (over: Partial<Role>): Role => ({
  id: 'r',
  slug: 'r',
  name: 'R',
  description: '',
  is_system: false,
  hierarchy_level: 50,
  has_full_data_access: false,
  permissions: [],
  permission_count: 10,
  members_count: 0,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
  ...over,
})

const OWNER = role({
  id: 'owner',
  slug: 'owner',
  name: 'Owner',
  is_system: true,
  hierarchy_level: 100,
  has_full_data_access: true,
  members_count: 1,
  summary: { risk: 'critical', reasons: ['admin'], areas: [] },
})
const TRIAGE = role({
  id: 'triage',
  slug: 'triage-lead',
  name: 'Triage lead',
  description: 'Approves false positives and accepted risk',
  members_count: 6,
  permission_count: 27,
  summary: { risk: 'medium', reasons: ['approve'], areas: [{ area: 'findings', level: 'change' }] },
})
const PENTESTER = role({
  id: 'pentester',
  slug: 'pentester',
  name: 'Pentester',
  members_count: 4,
  summary: { risk: 'high', reasons: ['run_scans'], areas: [{ area: 'scans', level: 'change' }] },
})

let rolesState: { roles: Role[]; isError: boolean; error?: unknown }
const deleteRole = vi.fn()
vi.mock('@/features/access-control', async (orig) => ({
  ...(await orig<typeof import('@/features/access-control')>()),
  useRoles: () => ({ ...rolesState, isLoading: false, mutate: vi.fn() }),
  useDeleteRole: () => ({ deleteRole, isDeleting: false }),
  RoleDetailSheet: () => null,
  CreateRoleSheet: () => null,
  EditRoleSheet: () => null,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const show = (search = '') => {
  window.history.replaceState(null, '', `/settings/roles${search}`)
  return render(
    <I18nProvider locale="en">
      <RolesPage />
    </I18nProvider>
  )
}

beforeEach(() => {
  canMutate = true
  rolesState = { roles: [OWNER, TRIAGE, PENTESTER], isError: false }
  deleteRole.mockReset()
})

describe('Roles list', () => {
  it('shows every role with its risk, members and permissions', () => {
    show()
    const table = screen.getByRole('table')
    expect(within(table).getByRole('link', { name: 'Triage lead' })).toHaveAttribute(
      'href',
      '/settings/roles?role=triage'
    )
    expect(within(table).getByText('Full control')).toBeInTheDocument()
    expect(within(table).getByText('27')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Create role/ })).toBeInTheDocument()
    // No metric tiles: the filter chips replace them.
    expect(screen.queryByText('System roles')).toBeNull()
  })

  it('shows no Members column when the API sends no member counts (never a row of zeros)', () => {
    rolesState.roles = [OWNER, TRIAGE, PENTESTER].map(({ members_count: _drop, ...r }) => r)
    show()
    expect(screen.queryByRole('columnheader', { name: /Members/ })).toBeNull()
  })

  it('narrows by risk from the URL and shows it as a chip', () => {
    show('?risk=high')
    const table = screen.getByRole('table')
    expect(within(table).getByRole('link', { name: 'Pentester' })).toBeInTheDocument()
    expect(within(table).queryByRole('link', { name: 'Triage lead' })).toBeNull()
    expect(
      screen.getByRole('button', { name: 'Remove filter Risk: High risk' })
    ).toBeInTheDocument()
  })

  it('a list narrowed to custom roles with none says the system roles always exist', () => {
    rolesState.roles = [OWNER]
    show('?type=custom')
    expect(screen.getByText('No custom roles yet')).toBeInTheDocument()
    expect(screen.getByText(/Owner, Admin, Member and Viewer always exist/)).toBeInTheDocument()
  })

  it('a system role has no edit or delete: no row menu, its name opens it', () => {
    show()
    expect(screen.queryByRole('button', { name: 'Actions for Owner' })).toBeNull()
    expect(
      screen.getAllByRole('button', { name: 'Actions for Triage lead' }).length
    ).toBeGreaterThan(0)
    expect(screen.getAllByRole('link', { name: 'Owner' })[0]).toHaveAttribute(
      'href',
      '/settings/roles?role=owner'
    )
  })

  it('delete says how many members hold the role and needs its name typed', async () => {
    const user = userEvent.setup()
    show()
    await user.click(screen.getAllByRole('button', { name: 'Actions for Triage lead' })[0])
    await user.click(await screen.findByRole('menuitem', { name: /Delete role/ }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the role "Triage lead"?')
    expect(dialog).toHaveTextContent('6 members have this role now')
    expect(within(dialog).getByRole('button', { name: /Delete role/ })).toBeDisabled()
    expect(deleteRole).not.toHaveBeenCalled()
  })

  it('a reader without the create permission is told the page is view only', () => {
    canMutate = false
    show()
    expect(screen.getByText(/View only\. Only owners and administrators can change roles/))
    expect(screen.queryByRole('button', { name: /Create role/ })).toBeNull()
  })

  it('a failed read says so with Retry, not an empty list', () => {
    rolesState = { roles: [], isError: true, error: new Error('boom') }
    show()
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
    expect(screen.queryByText('No roles yet')).toBeNull()
  })
})
