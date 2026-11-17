/**
 * The members page shows its lists as tabs (`?tab=`): Current members for
 * everyone, Pending invitations for whoever may invite or manage members,
 * Requests to join for administrators. Each tab carries its count: the
 * organization-wide current members (none while the stats are unknown), the
 * pending invitations and the open join requests. A tab the reader may not
 * see is never shown, and a link to it lands on Current members.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { I18nProvider } from '@/context/i18n-provider'
import UsersPage from '../page'

const st = vi.hoisted(() => ({
  search: '',
  canInvite: true,
  admin: true,
  stats: { total_members: 12, active_members: 11, offboarded_members: 2 } as
    Record<string, number> | undefined,
  invitations: [] as unknown[],
  requests: [] as unknown[],
  lastLogin: undefined as string | undefined,
}))

const invitation = (id: string) => ({
  id,
  email: `${id}@example.com`,
  role: 'member',
  role_ids: [],
  expires_at: '2099-01-01T00:00:00Z',
  created_at: '2026-11-01T00:00:00Z',
})

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/settings/members',
  useSearchParams: () => new URLSearchParams(st.search),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { slug: 'acme' } }),
}))
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'u-self' }) }))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: ReactNode }) => <>{children}</>,
  Permission: { MembersInvite: 'members:invite', MembersManage: 'members:manage' },
  usePermissions: () => ({
    // The row menu hides route-gated items by these (an owner passes).
    permissions: ['team:roles:assign', 'team:members:write'],
    can: () => true,
    isLoading: false,
    tenantRole: 'owner',
    isOwner: () => true,
    isAtLeast: () => st.admin,
    canAny: () => st.canInvite,
  }),
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
// The page reads the join requests for its tab count (the card's own read, shared).
vi.mock('@/features/organization/api/use-domain-signup', () => ({
  useJoinRequests: (enabled: boolean) => ({ requests: enabled ? st.requests : [] }),
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
        last_login_at: st.lastLogin,
      },
    ],
    total: 1,
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
  useMemberStats: () => ({ stats: st.stats, mutate: vi.fn() }),
  useInvitations: () => ({ invitations: st.invitations, mutate: vi.fn() }),
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

function renderPage() {
  window.history.replaceState(null, '', `/settings/members${st.search ? `?${st.search}` : ''}`)
  return render(
    <I18nProvider locale="en">
      <UsersPage />
    </I18nProvider>
  )
}

/** The tabs as "name count" pairs, in order. */
function tabs() {
  return screen.queryAllByRole('tab').map((tab) => ({
    name: tab.firstChild?.textContent ?? '',
    count: tab.querySelector('[data-slot="tabs-count"]')?.textContent ?? null,
    selected: tab.getAttribute('aria-selected') === 'true',
  }))
}

afterEach(() => {
  st.search = ''
  st.canInvite = true
  st.admin = true
  st.stats = { total_members: 12, active_members: 11, offboarded_members: 2 }
  st.invitations = []
  st.requests = []
  st.lastLogin = undefined
})

describe('Members page tabs and counts', () => {
  it('shows the three lists with their counts to an administrator', () => {
    st.invitations = [invitation('a'), invitation('b')]
    st.requests = [{ id: 'r1' }, { id: 'r2' }, { id: 'r3' }]
    renderPage()
    const list = screen.getByRole('tablist', { name: 'Member lists' })
    expect(within(list).getAllByRole('tab')).toHaveLength(3)
    expect(tabs()).toEqual([
      { name: 'Current members', count: '12', selected: true },
      { name: 'Pending invitations', count: '2', selected: false },
      { name: 'Requests to join', count: '3', selected: false },
    ])
  })

  it('shows no current-members count while the organization stats are unknown', () => {
    st.stats = undefined
    renderPage()
    expect(tabs()[0]).toEqual({ name: 'Current members', count: null, selected: true })
  })

  it('hides Requests to join from someone below administrator', () => {
    st.admin = false
    st.requests = [{ id: 'r1' }]
    renderPage()
    expect(tabs().map((t) => t.name)).toEqual(['Current members', 'Pending invitations'])
  })

  it('hides Pending invitations from someone who may not invite or manage members', () => {
    st.canInvite = false
    st.invitations = [invitation('a')]
    renderPage()
    expect(tabs().map((t) => t.name)).toEqual(['Current members', 'Requests to join'])
  })

  it('shows no tab list when Current members is the only list', () => {
    st.canInvite = false
    st.admin = false
    renderPage()
    expect(screen.queryByRole('tablist')).toBeNull()
    expect(screen.getByRole('searchbox', { name: 'Search members' })).toBeInTheDocument()
  })

  it('opens the tab named in the URL', () => {
    st.search = 'tab=requests'
    renderPage()
    expect(tabs().find((t) => t.selected)?.name).toBe('Requests to join')
  })

  it('lands on Current members when the URL names a tab the reader may not see', () => {
    st.search = 'tab=requests'
    st.admin = false
    renderPage()
    expect(tabs().find((t) => t.selected)?.name).toBe('Current members')
    expect(screen.getByRole('searchbox', { name: 'Search members' })).toBeInTheDocument()
  })

  it('says "1 hour ago", not "1 hours ago"', () => {
    st.lastLogin = new Date(Date.now() - 61 * 60_000).toISOString()
    renderPage()
    expect(screen.getByText('1 hour ago')).toBeInTheDocument()
  })
})
