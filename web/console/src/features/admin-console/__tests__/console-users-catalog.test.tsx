import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const mocks = vi.hoisted(() => ({
  role: 'ops_admin' as string,
  usersCalls: [] as unknown[][],
  revoke: vi.fn(),
  stale: false,
  phone: false,
  imported: true,
  pkgsKnown: true,
  pkgTotal: 1,
}))

vi.mock('@/hooks/use-mobile', async (orig) => ({
  ...(await orig<typeof import('@/hooks/use-mobile')>()),
  useIsMobile: () => mocks.phone,
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
      revocations_stale: mocks.stale,
      imported_at: mocks.imported ? '2026-11-01T00:00:00Z' : undefined,
    },
    mutate: vi.fn(),
  }),
  useCatalogPackages: () => ({
    isLoading: !mocks.pkgsKnown,
    mutate: vi.fn(),
    data: !mocks.pkgsKnown
      ? undefined
      : {
          total: mocks.pkgTotal,
          data:
            mocks.pkgTotal === 0
              ? []
              : [
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
  mocks.imported = true
  mocks.pkgsKnown = true
  mocks.pkgTotal = 1
  window.history.replaceState(null, '', '/')
})

describe('Users list', () => {
  it('browses without a search, with a count on every state tab and no names', async () => {
    render(<UsersPage />)
    expect(mocks.usersCalls[0]).toEqual(['', 'all', 1, 25])
    await userEvent.click(screen.getByRole('button', { name: 'State: All' }))
    expect(screen.getByRole('menuitemradio', { name: /All\s*40/ })).toBeInTheDocument()
    expect(screen.getByRole('menuitemradio', { name: /Blocked\s*1/ })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('menuitemradio', { name: /Blocked/ }))
    await waitFor(() => expect(mocks.usersCalls.at(-1)?.[1]).toBe('blocked'))
  })

  it('is not shown to a read-only administrator', () => {
    mocks.role = 'readonly'
    render(<UsersPage />)
    expect(screen.queryByRole('button', { name: /State/ })).not.toBeInTheDocument()
  })
})

describe('Content catalog', () => {
  it('shows the trust roots read-only and lets a super admin revoke a version with a reason, the typed version and a code', async () => {
    mocks.role = 'super_admin'
    render(<CatalogPage />)
    expect(screen.getByText(/cannot be changed from this console/)).toBeInTheDocument()
    await userEvent.click(screen.getAllByText('Scanning sensor')[0])
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke' }))
    const confirm = screen.getAllByRole('button', { name: 'Revoke' }).at(-1)!
    expect(confirm).toBeDisabled()
    // Reason, the version typed and a fresh code: all three before Revoke.
    await userEvent.type(screen.getByLabelText(/^Reason/), 'withdrawn by the publisher')
    await userEvent.type(screen.getByLabelText('Code from your authenticator app'), '123456')
    expect(screen.getAllByRole('button', { name: 'Revoke' }).at(-1)!).toBeDisabled()
    await userEvent.type(screen.getByTestId('admin-confirm-typed'), '0.24.0')
    await userEvent.click(screen.getAllByRole('button', { name: 'Revoke' }).at(-1)!)
    await waitFor(() =>
      expect(mocks.revoke).toHaveBeenCalledWith(
        'openctem/sensor',
        '0.24.0',
        'withdrawn by the publisher',
        '123456'
      )
    )
  })

  it('lists the packages under a titled count, with the search and the type in the toolbar', () => {
    mocks.role = 'super_admin'
    render(<CatalogPage />)
    expect(screen.getByRole('heading', { name: /All packages/ })).toBeInTheDocument()
    expect(screen.getAllByText('1 package')).toHaveLength(1)
    const toolbar = screen.getByTestId('data-table-toolbar')
    expect(within(toolbar).getByRole('searchbox', { name: 'Search packages' })).toBeInTheDocument()
    expect(within(toolbar).getByRole('button', { name: /Package type/ })).toBeInTheDocument()
    // The catalog's two actions are the page's own, in its header.
    const header = screen
      .getByRole('heading', { level: 1, name: 'Content catalog' })
      .closest('[data-slot="page-header"]') as HTMLElement | null
    expect(header).not.toBeNull()
    expect(within(header!).getByRole('button', { name: /Import a bundle/ })).toBeEnabled()
    expect(within(header!).getByRole('button', { name: /Publish a package/ })).toBeInTheDocument()
    const table = screen.getByRole('table', { name: 'Catalog packages' })
    expect(within(table).getAllByText('openctem/sensor').length).toBeGreaterThan(0)
  })

  it('puts the list first and the trust state after it, with a marker when it is out of date', () => {
    mocks.stale = true
    try {
      render(<CatalogPage />)
      const table = screen.getByRole('table', { name: 'Catalog packages' })
      const trust = document.getElementById('catalog-trust')!
      expect(trust).not.toBeNull()
      expect(table.compareDocumentPosition(trust) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
      const marker = screen.getByRole('link', { name: 'Out of date' })
      expect(marker).toHaveAttribute('href', '#catalog-trust')
      expect(within(trust).getByText('The catalog is out of date')).toBeInTheDocument()
    } finally {
      mocks.stale = false
    }
  })

  it('shows a package on a phone in fixed slots, no label/value grid, a tap opens its versions', async () => {
    mocks.phone = true
    try {
      const user = userEvent.setup()
      render(<CatalogPage />)
      const card = document.querySelector('[data-slot="catalog-card"]') as HTMLElement
      expect(card).not.toBeNull()
      expect(within(card).getByText('Scanning sensor')).toBeInTheDocument()
      expect(within(card).getByText('openctem/sensor')).toBeInTheDocument()
      const kind = card.querySelector('[data-slot="catalog-card-kind"]') as HTMLElement
      expect(kind).toHaveTextContent('Signed catalog')
      const facts = card.querySelector('[data-slot="meta-line"]') as HTMLElement
      expect(facts).toHaveTextContent('Latest 0.24.0')
      expect(facts).toHaveTextContent('2 versions')
      expect(card.querySelector('dl, dt, dd')).toBeNull()
      expect(within(card).queryByText('Versions')).toBeNull()
      await user.click(card)
      expect(await screen.findByRole('dialog')).toBeInTheDocument()
    } finally {
      mocks.phone = false
    }
  })

  it('shows no marker while the catalog is current', () => {
    render(<CatalogPage />)
    expect(screen.queryByRole('link', { name: 'Out of date' })).not.toBeInTheDocument()
  })

  it('does not say nothing was imported while packages are listed', () => {
    mocks.imported = false
    render(<CatalogPage />)
    expect(screen.getByRole('table', { name: 'Catalog packages' })).toBeInTheDocument()
    expect(screen.queryByText('No catalog has been imported yet')).not.toBeInTheDocument()
    // The trust details stay.
    expect(screen.getByText(/cannot be changed from this console/)).toBeInTheDocument()
  })

  it('says nothing was imported when no package is listed', () => {
    mocks.imported = false
    mocks.pkgTotal = 0
    render(<CatalogPage />)
    expect(screen.getByText('No catalog has been imported yet')).toBeInTheDocument()
  })

  it('draws nothing under the list before the package list is known', () => {
    mocks.imported = false
    mocks.pkgsKnown = false
    render(<CatalogPage />)
    expect(screen.queryByText('No catalog has been imported yet')).not.toBeInTheDocument()
    expect(document.getElementById('catalog-trust')).toBeNull()
  })

  it('offers no change to an operations administrator', () => {
    render(<CatalogPage />)
    expect(screen.queryByRole('button', { name: /Import a bundle/ })).not.toBeInTheDocument()
  })
})
