import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const mocks = vi.hoisted(() => ({
  role: 'ops_admin' as string,
  usersCalls: [] as unknown[][],
  revoke: vi.fn(),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../components/admin-console-shell', () => ({
  useAdmin: () => ({ role: mocks.role }),
  useAdminOrNull: () => ({ role: mocks.role }),
}))
vi.mock('../api/use-platform-users', async (orig) => ({
  ...(await orig<typeof import('../api/use-platform-users')>()),
  usePlatformUsers: (...args: unknown[]) => {
    mocks.usersCalls.push(args)
    return {
      isLoading: false,
      mutate: vi.fn(),
      data: {
        data: [
          {
            id: 'u1',
            email: 'person@corp.test',
            status: 'suspended',
            auth_provider: 'local',
            email_verified: true,
            locked: false,
            blocked: true,
            created_at: '2026-10-01T00:00:00Z',
            memberships: 2,
            mfa_enabled: false,
            is_platform_admin: false,
            erased: false,
          },
        ],
        total: 1,
        page: 1,
        per_page: 25,
        total_pages: 1,
        counts: {
          all: 40,
          active: 30,
          blocked: 1,
          locked: 2,
          unverified: 5,
          mfa_off: 20,
          platform_admins: 3,
        },
      },
    }
  },
}))
vi.mock('../api/use-content-catalog', async (orig) => ({
  ...(await orig<typeof import('../api/use-content-catalog')>()),
  useCatalogTrust: () => ({
    data: {
      roots_configured: 1,
      keyset_version: 2,
      index_sequence: 10,
      index_expired: false,
      revocations_sequence: 1,
      revocations_stale: false,
    },
    mutate: vi.fn(),
  }),
  useCatalogPackages: () => ({
    isLoading: false,
    mutate: vi.fn(),
    data: {
      total: 1,
      data: [
        {
          versions: 2,
          latest: {
            id: 'p1',
            package_id: 'openctem/sensor',
            version: '0.24.0',
            type: 'sensors',
            origin: 'catalog',
            title: 'Scanning sensor',
            revoked: false,
            signatures: ['catalog'],
          },
        },
      ],
    },
  }),
  useCatalogVersions: (id: string | null) => ({
    isLoading: false,
    mutate: vi.fn(),
    data: id
      ? {
          package_id: id,
          versions: [{ id: 'v1', version: '0.24.0', revoked: false, signatures: ['catalog'] }],
        }
      : undefined,
  }),
  revokeCatalogVersion: mocks.revoke,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const { default: UsersPage } = await import('@console/app/(console)/users/page')
const { default: CatalogPage } =
  await import('@console/app/(console)/scanning/content-catalog/page')

beforeEach(() => {
  mocks.role = 'ops_admin'
  mocks.usersCalls.length = 0
  mocks.revoke.mockReset().mockResolvedValue({})
  window.history.replaceState(null, '', '/')
})

describe('Users list', () => {
  it('browses without a search, with a count on every state tab and no names', async () => {
    render(<UsersPage />)
    expect(mocks.usersCalls[0]).toEqual(['', 'all', 1, 25])
    expect(screen.getByRole('tab', { name: /All\s*40/ })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Blocked\s*1/ })).toBeInTheDocument()
    expect(screen.getAllByText('person@corp.test').length).toBeGreaterThan(0)
    await userEvent.click(screen.getByRole('tab', { name: /Blocked/ }))
    await waitFor(() => expect(mocks.usersCalls.at(-1)?.[1]).toBe('blocked'))
  })

  it('is not shown to a read-only administrator', () => {
    mocks.role = 'readonly'
    render(<UsersPage />)
    expect(screen.queryByRole('tab', { name: /All/ })).not.toBeInTheDocument()
  })
})

describe('Content catalog', () => {
  it('shows the trust roots read-only and lets a super admin revoke a version with a reason', async () => {
    mocks.role = 'super_admin'
    render(<CatalogPage />)
    expect(screen.getByText(/cannot be changed from this console/)).toBeInTheDocument()
    await userEvent.click(screen.getAllByText('Scanning sensor')[0])
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke' }))
    const confirm = screen.getAllByRole('button', { name: 'Revoke' }).at(-1)!
    expect(confirm).toBeDisabled()
    await userEvent.type(screen.getByLabelText('Reason'), 'withdrawn by the publisher')
    await userEvent.click(screen.getAllByRole('button', { name: 'Revoke' }).at(-1)!)
    await waitFor(() =>
      expect(mocks.revoke).toHaveBeenCalledWith(
        'openctem/sensor',
        '0.24.0',
        'withdrawn by the publisher'
      )
    )
  })

  it('offers no change to an operations administrator', () => {
    render(<CatalogPage />)
    expect(screen.queryByRole('button', { name: /Import a bundle/ })).not.toBeInTheDocument()
  })
})
