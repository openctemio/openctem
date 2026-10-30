/**
 * Erase personal data: an offboarded member's row menu opens the typed
 * confirmation, and the API is called only after the member's email is typed.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { I18nProvider } from '@/context/i18n-provider'
import UsersPage from '../page'

const erase = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))

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
  eraseMemberPersonalData: erase,
  useMembers: () => ({
    members: [
      {
        id: 'm1',
        user_id: 'u1',
        name: 'Lan Tran',
        email: 'lan@acme.example',
        role: 'member',
        status: 'offboarded',
        joined_at: '2026-10-01T00:00:00Z',
      },
    ],
    total: 1,
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
  useMemberStats: () => ({
    stats: { current: 0, active: 0, suspended: 0, offboarded: 1 },
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

describe('Members page erase personal data', () => {
  it('opens the typed confirmation from the row menu and erases only after the email is typed', async () => {
    const user = userEvent.setup()
    render(
      <I18nProvider locale="en">
        <UsersPage />
      </I18nProvider>
    )
    await user.click(screen.getByRole('button', { name: /Actions for Lan Tran/ }))
    await user.click(await screen.findByRole('menuitem', { name: /Erase personal data/ }))

    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Erase the personal data of Lan Tran?')
    const confirm = screen.getByRole('button', { name: /^Erase$/ })
    expect(confirm).toBeDisabled()
    await user.click(confirm)
    expect(erase).not.toHaveBeenCalled()

    await user.type(screen.getByRole('textbox'), 'lan@acme.example')
    expect(confirm).toBeEnabled()
    await user.click(confirm)
    await waitFor(() => expect(erase).toHaveBeenCalledWith('m1'))
  })
})
