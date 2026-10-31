/**
 * The members page speaks the reader's language: the title, filters, table
 * header, pagination tail ("thành viên", not "users") and the filter selects'
 * accessible names all come from the vi catalog.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { I18nProvider } from '@/context/i18n-provider'
import UsersPage from '../page'

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/settings/members',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { slug: 'acme' } }),
}))
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'u-self' }) }))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: ReactNode }) => <>{children}</>,
  usePermissions: () => ({ isOwner: () => true, isAtLeast: () => true }),
  useCanMutate: () => true,
}))
vi.mock('@/features/access-control', () => ({
  useUserRoles: () => ({ roles: [], isLoading: false, mutate: vi.fn() }),
  useRoles: () => ({ roles: [], isLoading: false }),
  useSetUserRoles: () => ({ setUserRoles: vi.fn(), isSetting: false }),
}))
vi.mock('@/features/organization/api/use-tenant-settings', () => ({
  useTenantSettings: () => ({ settings: undefined }),
}))
vi.mock('@/features/organization/api/use-ownership-transfer', () => ({
  usePendingOwnershipTransfer: () => ({ transfer: undefined, mutate: vi.fn() }),
}))
vi.mock('@/features/organization/components/join-requests-card', () => ({
  JoinRequestsCard: () => null,
}))
vi.mock('@/features/organization/components/ownership-transfer-banner', () => ({
  OwnershipTransferBanner: () => null,
}))
vi.mock('@/features/organization/components/transfer-ownership-dialog', () => ({
  TransferOwnershipDialog: () => null,
}))
vi.mock('@/features/organization/components/member-access-dialog', () => ({
  MemberAccessDialog: () => null,
}))
vi.mock('@/features/organization', async (orig) => ({
  ...(await orig<typeof import('@/features/organization')>()),
  useMembers: () => ({
    members: [
      {
        id: 'm1',
        user_id: 'u1',
        name: 'Lan Tran',
        email: 'lan@acme.example',
        role: 'member',
        status: 'active',
        joined_at: '2026-10-01T00:00:00Z',
      },
    ],
    total: 1,
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
  useMemberStats: () => ({
    stats: { current: 1, active: 1, suspended: 0, offboarded: 0 },
    mutate: vi.fn(),
  }),
  useInvitations: () => ({ invitations: [], mutate: vi.fn() }),
  useMemberAccessReport: () => ({ report: undefined, isLoading: false }),
  AddUserDialog: () => null,
  InviteUserDialog: () => null,
  SetupLinkDialog: () => null,
  OffboardMemberDialog: () => null,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe('Members page (vi)', () => {
  it('renders Vietnamese copy, a translated pagination noun and labelled filters', () => {
    render(
      <I18nProvider locale="vi">
        <UsersPage />
      </I18nProvider>
    )
    expect(screen.getByRole('heading', { level: 1, name: 'Thành viên' })).toBeInTheDocument()
    expect(screen.getByText('Mời người dùng')).toBeInTheDocument()
    expect(screen.getByText('Thêm người dùng')).toBeInTheDocument()
    expect(screen.getByText('Hoạt động gần nhất')).toBeInTheDocument()
    expect(screen.getByText(/trên 1 thành viên/)).toBeInTheDocument()
    // The filters are filter tokens: "Status: Current members", whole.
    expect(
      screen.getByRole('button', { name: 'Trạng thái: Thành viên hiện tại' })
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Vai trò: Tất cả vai trò' })).toBeInTheDocument()
    expect(screen.getByRole('searchbox', { name: 'Tìm thành viên' })).toBeInTheDocument()
    expect(screen.queryByText('Invite user')).toBeNull()
    expect(screen.queryByText('Last active')).toBeNull()
    expect(screen.queryByText(/of 1 users/)).toBeNull()
  })
})
