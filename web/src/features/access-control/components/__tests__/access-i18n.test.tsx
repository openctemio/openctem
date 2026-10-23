/**
 * Roles, teams and the add-user dialog speak the reader's language: headings,
 * table headers, actions and form labels come from the vi catalog and the old
 * English copy is gone.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { I18nProvider } from '@/context/i18n-provider'
import RolesPage from '@/app/(dashboard)/settings/roles/page'
import TeamsPage from '@/app/(dashboard)/settings/teams/page'
import { AddUserDialog } from '@/features/organization/components/add-user-dialog'

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/settings/roles',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { slug: 'acme' } }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: ReactNode }) => <>{children}</>,
  useHasPermission: () => true,
  useCanMutate: () => true,
}))
vi.mock('@/features/access-control', async (orig) => ({
  ...(await orig<typeof import('@/features/access-control')>()),
  useRoles: () => ({
    roles: [
      {
        id: 'r1',
        name: 'Analyst',
        slug: 'analyst',
        is_system: false,
        has_full_data_access: false,
        hierarchy_level: 50,
        permission_count: 3,
        created_at: '2026-10-01T00:00:00Z',
      },
    ],
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
  useDeleteRole: () => ({ deleteRole: vi.fn() }),
  useGroups: () => ({
    groups: [
      {
        id: 'g1',
        name: 'Red team',
        member_count: 2,
        asset_count: 4,
        created_at: '2026-10-01T00:00:00Z',
      },
    ],
    uniqueMemberCount: 2,
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
  useCreateGroup: () => ({ createGroup: vi.fn(), isCreating: false }),
  useDeleteGroup: () => ({ deleteGroup: vi.fn(), isDeleting: false }),
  RoleDetailSheet: () => null,
  CreateRoleSheet: () => null,
  EditRoleSheet: () => null,
}))
vi.mock('@/features/access-control/components/group-detail-sheet', () => ({
  GroupDetailSheet: () => null,
}))
vi.mock('@/features/access-control/components/assignment-rules-section', () => ({
  AssignmentRulesSection: () => null,
}))
vi.mock('@/features/organization/components/role-checklist', () => ({
  RoleChecklist: () => null,
  defaultViewerRoleId: () => undefined,
}))
vi.mock('@/features/organization/api/use-members', () => ({
  createTenantUser: vi.fn(),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const vi_ = (ui: ReactNode) => render(<I18nProvider locale="vi">{ui}</I18nProvider>)

describe('Access settings (vi)', () => {
  it('roles page', () => {
    vi_(<RolesPage />)
    expect(screen.getByRole('heading', { level: 1, name: 'Vai trò' })).toBeInTheDocument()
    expect(screen.getByText('Tạo vai trò')).toBeInTheDocument()
    expect(screen.getByText('Quyền truy cập dữ liệu')).toBeInTheDocument()
    expect(screen.getByText('Theo nhóm')).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Tìm vai trò' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Loại vai trò' })).toBeInTheDocument()
    expect(screen.queryByText('Create role')).toBeNull()
    expect(screen.queryByText('Team-based')).toBeNull()
  })

  it('teams page', () => {
    vi_(<TeamsPage />)
    expect(screen.getByRole('heading', { level: 1, name: 'Nhóm' })).toBeInTheDocument()
    expect(screen.getByText('Tạo nhóm')).toBeInTheDocument()
    expect(screen.getByText('Tài sản đã gán')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Quy tắc gán' })).toBeInTheDocument()
    expect(screen.queryByText('Create team')).toBeNull()
    expect(screen.queryByText('Assigned assets')).toBeNull()
  })

  it('add user dialog', () => {
    vi_(<AddUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    expect(screen.getByText('Thêm người dùng', { selector: 'h2' })).toBeInTheDocument()
    expect(screen.getByLabelText('Tên')).toBeInTheDocument()
    expect(screen.getByText('Gán vai trò')).toBeInTheDocument()
    expect(screen.queryByText('Assign roles')).toBeNull()
  })
})
