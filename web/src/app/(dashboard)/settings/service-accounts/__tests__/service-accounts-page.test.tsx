import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ServiceAccountsPage from '../page'

// Radix Select (key expiry) measures itself; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const mockCreateAccount = vi.fn()
const mockDeleteAccount = vi.fn()
const mockCreateKey = vi.fn()
const mockDeleteKey = vi.fn()
let accounts: unknown[] = []
let mayMutate = true
let listError: unknown = undefined

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 'acme', role: 'owner' } }),
}))
vi.mock('@/features/service-accounts/api/use-service-accounts', () => ({
  useServiceAccounts: () => ({
    data: listError ? undefined : { data: accounts },
    error: listError,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useCreateServiceAccount: () => ({ trigger: mockCreateAccount, isMutating: false }),
  useDeleteServiceAccount: () => ({ trigger: mockDeleteAccount, isMutating: false }),
  useServiceAccountKeys: () => ({
    data: {
      data: [
        {
          id: 'k1',
          name: 'prod connector',
          key_prefix: 'oct_abcd',
          scopes: ['findings:read'],
          status: 'active',
          rate_limit: 0,
          use_count: 0,
          created_at: '2026-10-01T00:00:00Z',
          updated_at: '2026-10-01T00:00:00Z',
        },
      ],
      total: 1,
    },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useCreateServiceAccountKey: () => ({ trigger: mockCreateKey, isMutating: false }),
  useDeleteServiceAccountKey: () => ({ trigger: mockDeleteKey, isMutating: false }),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/settings/service-accounts',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: vi.fn(async () => true) }))
vi.mock('@/lib/permissions', async (importOriginal) => {
  const mod = await importOriginal<typeof import('@/lib/permissions')>()
  const all = Object.values(mod.Permission) as string[]
  return {
    ...mod,
    Can: ({ children }: { children: React.ReactNode }) => (mayMutate ? children : null),
    useCanMutate: () => mayMutate,
    usePermissions: () => ({
      permissions: mayMutate ? all : [],
      can: () => mayMutate,
      isAdmin: () => mayMutate,
      isLoading: false,
      tenantRole: mayMutate ? 'owner' : 'viewer',
    }),
  }
})

const account = {
  id: 'sa1',
  name: 'SIEM export',
  description: 'ships findings',
  owner_name: 'Alice',
  status: 'active',
  api_keys: 1,
  created_at: '2026-10-01T00:00:00Z',
}

describe('ServiceAccountsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    accounts = []
    mayMutate = true
    listError = undefined
    window.history.replaceState(null, '', '/settings/service-accounts')
  })

  it('creates a service account from the empty state', async () => {
    mockCreateAccount.mockResolvedValueOnce({ id: 'sa1' })
    render(<ServiceAccountsPage />)
    expect(screen.getByText('No service accounts yet')).toBeInTheDocument()

    await userEvent.click(screen.getAllByRole('button', { name: /new service account/i })[0])
    await userEvent.type(screen.getByLabelText('Name'), '  SIEM export ')
    await userEvent.click(screen.getByRole('button', { name: /^create$/i }))

    expect(mockCreateAccount).toHaveBeenCalledWith({ name: 'SIEM export', description: undefined })
  })

  it('keeps the name link on this page when an id looks like a script address', () => {
    accounts = [{ ...account, id: 'javascript:alert(1)' }]
    render(<ServiceAccountsPage />)
    const href = screen.getByRole('link', { name: 'SIEM export' }).getAttribute('href') ?? ''
    expect(href.toLowerCase()).not.toMatch(/^(javascript|data|vbscript):/)
    expect(href.startsWith('/settings/service-accounts')).toBe(true)
  })

  it('lists accounts and mints a key for one, shown once', async () => {
    accounts = [account]
    mockCreateKey.mockResolvedValueOnce({ key: 'oct_secret_for_sa' })
    render(<ServiceAccountsPage />)
    expect(screen.getByText('SIEM export')).toBeInTheDocument()
    expect(screen.getByText('Alice')).toBeInTheDocument()

    // The name opens the account's keys (a link to ?account=<id>).
    await userEvent.click(screen.getByRole('link', { name: 'SIEM export' }))
    expect(await screen.findByText('prod connector')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /generate key/i }))
    await userEvent.type(screen.getByLabelText('Name'), 'connector')
    await userEvent.click(screen.getByRole('button', { name: /^generate$/i }))

    expect(mockCreateKey).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'connector', scopes: ['assets:read', 'findings:read'] })
    )
    expect(await screen.findByText('oct_secret_for_sa')).toBeInTheDocument()
  })

  it('deletes an account only after confirmation', async () => {
    accounts = [account]
    mockDeleteAccount.mockResolvedValueOnce(undefined)
    render(<ServiceAccountsPage />)

    await userEvent.click(screen.getAllByRole('button', { name: 'Actions for SIEM export' })[0])
    await userEvent.click(await screen.findByRole('menuitem', { name: /Delete service account/ }))
    expect(mockDeleteAccount).not.toHaveBeenCalled()
    // Deleting a service account cuts off its integrations: type its name first.
    const confirm = screen.getByRole('button', { name: /^delete$/i })
    expect(confirm).toBeDisabled()
    await userEvent.type(screen.getByRole('textbox'), 'SIEM export')
    await userEvent.click(confirm)
    expect(mockDeleteAccount).toHaveBeenCalledWith('sa1')
  })

  it('hides every action from someone who may only read', () => {
    accounts = [account]
    mayMutate = false
    render(<ServiceAccountsPage />)
    expect(screen.getByText('SIEM export')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /new service account/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'SIEM export' })).not.toBeInTheDocument()
    expect(screen.getByText(/View only/)).toBeInTheDocument()
  })

  it('a failed read keeps the page and offers Retry', () => {
    listError = new Error('boom')
    render(<ServiceAccountsPage />)
    expect(screen.getByRole('heading', { level: 1, name: 'Service accounts' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
    expect(screen.queryByText('No service accounts yet')).not.toBeInTheDocument()
  })
})
