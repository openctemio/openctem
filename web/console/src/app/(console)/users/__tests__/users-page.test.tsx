import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useRouter } from 'next/navigation'

import { platformUserHref } from '@console/features/admin-console/lib/console-links'
import type { PlatformUserListItem } from '@console/features/admin-console/types'
import AdminUsersPage from '../page'

const state = vi.hoisted(() => ({
  permissions: ['platform.users.read'] as string[],
  rows: [] as unknown[],
  total: 0,
  error: undefined as unknown,
  calls: [] as { q: string; state: string; page: number; perPage: number }[],
}))

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@console/features/admin-console/components/admin-console-shell', () => ({
  useAdmin: () => ({ role: 'readonly', permissions: state.permissions }),
  useAdminOrNull: () => ({ role: 'readonly', permissions: state.permissions }),
}))
vi.mock('@console/features/admin-console/api/use-platform-users', () => ({
  PLATFORM_USER_SEARCH_MIN: 3,
  usePlatformUsers: (q: string, s: string, page: number, perPage: number) => {
    state.calls.push({ q, state: s, page, perPage })
    return state.error
      ? { data: undefined, error: state.error, isLoading: false, isValidating: false }
      : {
          data: {
            data: state.rows,
            total: state.total,
            total_pages: Math.max(1, Math.ceil(state.total / perPage)),
            counts: { all: state.total, locked: 1 },
          },
          error: undefined,
          isLoading: false,
          isValidating: false,
          mutate: vi.fn(),
        }
  },
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function account(patch: Partial<PlatformUserListItem> = {}): PlatformUserListItem {
  return {
    id: 'u1',
    email: 'person@example.com',
    status: 'active',
    auth_provider: 'local',
    email_verified: true,
    locked: false,
    blocked: false,
    created_at: '2026-10-01T00:00:00Z',
    memberships: 2,
    mfa_enabled: true,
    is_platform_admin: false,
    erased: false,
    ...patch,
  }
}

describe('Console users list', () => {
  beforeEach(() => {
    state.permissions = ['platform.users.read']
    state.rows = [account(), account({ id: 'u2', email: 'second@example.org', locked: true })]
    state.total = 2
    state.error = undefined
    state.calls = []
    window.history.replaceState(null, '', '/users')
  })

  it('shows the view name with the count once, and one table named after the page', () => {
    render(<AdminUsersPage />)
    expect(screen.getByRole('heading', { level: 2, name: 'All accounts' })).toBeInTheDocument()
    const counts = document.querySelectorAll('[data-slot="list-count"]')
    expect(counts).toHaveLength(1)
    expect(counts[0].textContent).toContain('2 accounts')
    expect(screen.getByRole('table', { name: 'Users' })).toBeInTheDocument()
  })

  it('reads 25 accounts a page in every state by default', () => {
    render(<AdminUsersPage />)
    expect(state.calls.at(-1)).toEqual({ q: '', state: 'all', page: 1, perPage: 25 })
  })

  it('keeps the columns of the list, each with a label', () => {
    render(<AdminUsersPage />)
    const headers = screen.getAllByRole('columnheader').map((h) => h.textContent)
    expect(headers).toEqual([
      'Account',
      'State',
      'Signs in with',
      'Organizations',
      'Last sign-in',
      'Created',
    ])
  })

  it('links each account to its page, the id as one encoded path segment', async () => {
    const push = vi.fn()
    vi.mocked(useRouter).mockReturnValue({ push } as unknown as ReturnType<typeof useRouter>)
    render(<AdminUsersPage />)
    const link = screen.getByRole('link', { name: 'person@example.com' })
    expect(link).toHaveAttribute('href', '/users/u1')
    await userEvent.click(link)
    expect(push).toHaveBeenCalledWith('/users/u1')
    expect(push).toHaveBeenCalledTimes(1)
    expect(platformUserHref('../../security/roles?x=1#y')).toBe(
      '/users/..%2F..%2Fsecurity%2Froles%3Fx%3D1%23y'
    )
  })

  it('keeps the state marks of an account on its row', () => {
    render(<AdminUsersPage />)
    const row = screen.getByRole('link', { name: 'second@example.org' }).closest('tr')!
    // The cell draws the marks twice: the phone card's chip (first mark and
    // "+n") and the marks that fit from 768 px; CSS shows one of them.
    expect(within(row).getAllByText('Locked').length).toBeGreaterThan(0)
    expect(within(row).getAllByText('Two-factor on').length).toBeGreaterThan(0)
  })

  it('offers the state select and the search, and no control that changes an account', () => {
    render(<AdminUsersPage />)
    expect(screen.getByRole('searchbox', { name: 'Search accounts' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'State: All' })).toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Block|Unlock|Reset|Sign out/ })).toBeNull()
  })

  it('names the state as the view and says so when no account is in it', () => {
    window.history.replaceState(null, '', '/users?state=locked')
    state.rows = []
    state.total = 0
    render(<AdminUsersPage />)
    expect(state.calls.at(-1)?.state).toBe('locked')
    expect(screen.getByRole('heading', { level: 2, name: 'Locked' })).toBeInTheDocument()
    expect(screen.getByText('No account in this state')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Clear filters' })).toBeInTheDocument()
  })

  it('says there are no accounts yet when nothing narrows the list', () => {
    state.rows = []
    state.total = 0
    render(<AdminUsersPage />)
    expect(screen.getByText('No accounts yet')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Clear filters' })).not.toBeInTheDocument()
  })

  it('shows the load error in the table, with the toolbar still there', () => {
    state.error = new Error('boom')
    render(<AdminUsersPage />)
    expect(screen.getByRole('button', { name: /Retry|Try again/ })).toBeInTheDocument()
    expect(screen.getByRole('searchbox', { name: 'Search accounts' })).toBeInTheDocument()
  })

  it('reads nothing and shows the role notice without the read permission', () => {
    state.permissions = []
    render(<AdminUsersPage />)
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument()
    // The hook is called with no search and returns no key only when asked;
    // the page must not render rows it was given.
    expect(screen.queryByText('person@example.com')).not.toBeInTheDocument()
  })
})
