/**
 * Changing roles: giving a member more access (a custom role added) asks first
 * and names what is added; the roles API is called only after confirming.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { I18nProvider } from '@/context/i18n-provider'
import UsersPage from '../page'

const setUserRoles = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))

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
  useRoles: () => ({
    roles: [
      {
        id: 'rc',
        slug: 'auditor',
        name: 'Auditor',
        description: '',
        is_system: false,
        permission_count: 3,
      },
    ],
    isLoading: false,
  }),
  useSetUserRoles: () => ({ setUserRoles, isSetting: false }),
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
  useUpdateMemberRole: () => ({ updateRole: vi.fn(), isUpdating: false }),
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

describe('Members page role grant confirmation', () => {
  it('asks before adding a role and saves only after confirming', async () => {
    const user = userEvent.setup()
    render(
      <I18nProvider locale="en">
        <UsersPage />
      </I18nProvider>
    )
    await user.click(screen.getByRole('button', { name: /Actions for Lan Tran/ }))
    await user.click(await screen.findByRole('menuitem', { name: /Change roles/ }))
    const dialog = await screen.findByRole('dialog')
    await user.click(await within(dialog).findByText('Auditor'))
    await user.click(within(dialog).getByRole('button', { name: 'Save changes' }))

    const confirm = await screen.findByRole('alertdialog')
    expect(confirm).toHaveTextContent('Give Lan Tran more access?')
    expect(confirm).toHaveTextContent('Roles added: Auditor.')
    expect(setUserRoles).not.toHaveBeenCalled()
    await user.click(within(confirm).getByRole('button', { name: 'Give access' }))
    await waitFor(() => expect(setUserRoles).toHaveBeenCalledWith({ role_ids: ['rc'] }))
  })
})
