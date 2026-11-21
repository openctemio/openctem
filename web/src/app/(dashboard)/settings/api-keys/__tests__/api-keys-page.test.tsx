/**
 * The API keys page (board P4-Settings-ApiKeys): owners and administrators get
 * the maximum lifetime section above the list, anyone else only their own
 * keys and no policy; a failed read keeps the page and offers Retry in the
 * list; a list sort reaches the request.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { I18nProvider } from '@/context/i18n-provider'
import type { APIKeyListParams } from '@/features/api-keys/api/use-api-keys'
import APIKeysPage from '../page'

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 'acme', role: 'owner' } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/settings/api-keys',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))

let admin = true
vi.mock('@/lib/permissions', async (orig) => {
  const mod = await orig<typeof import('@/lib/permissions')>()
  const all = Object.values(mod.Permission) as string[]
  return {
    ...mod,
    Can: ({ children }: { children: ReactNode }) => <>{children}</>,
    usePermissions: () => ({
      permissions: admin ? all : [],
      isAdmin: () => admin,
      isOwner: () => admin,
      can: () => admin,
      isLoading: false,
      tenantRole: admin ? 'owner' : 'member',
    }),
    useCanMutate: () => admin,
  }
})

const seen: APIKeyListParams[] = []
let listState: { data?: unknown; error?: unknown }
vi.mock('@/features/api-keys/api/use-api-keys', () => ({
  useApiKeys: (p: APIKeyListParams) => {
    seen.push(p)
    return { ...listState, isLoading: false, isValidating: false, mutate: vi.fn() }
  },
  useCreateApiKey: () => ({ trigger: vi.fn(), isMutating: false }),
  useRevokeApiKey: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteApiKey: () => ({ trigger: vi.fn(), isMutating: false }),
  useApiKeyPolicy: () => ({
    data: { max_lifetime_days: 90, default_max_lifetime_days: 90, ceiling_days: 365 },
    mutate: vi.fn(),
  }),
  updateApiKeyPolicy: vi.fn(),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const KEY = {
  id: 'k1',
  name: 'Nightly export script',
  key_prefix: 'oct_7f3a',
  scopes: ['assets:read', 'findings:read'],
  rate_limit: 0,
  status: 'active',
  use_count: 0,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
}

const show = (search = '') => {
  window.history.replaceState(null, '', `/settings/api-keys${search}`)
  return render(
    <I18nProvider locale="en">
      <APIKeysPage />
    </I18nProvider>
  )
}

beforeEach(() => {
  admin = true
  seen.length = 0
  listState = { data: { data: [KEY], total: 1, page: 1, per_page: 25, total_pages: 1 } }
})

describe('API keys page', () => {
  it('owners and administrators get the lifetime section and the list', () => {
    show()
    expect(screen.getByRole('heading', { level: 1, name: 'API keys' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Maximum key lifetime' })).toBeInTheDocument()
    expect(screen.getAllByText('Nightly export script').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: /Generate API key/ })).toBeInTheDocument()
  })

  it('anyone else sees only their own keys and no lifetime policy', () => {
    admin = false
    show()
    expect(screen.queryByRole('heading', { name: 'Maximum key lifetime' })).toBeNull()
    expect(screen.getByText(/Your own keys/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Generate API key/ })).toBeNull()
  })

  it('a failed read keeps the page and offers Retry, never "No API keys yet"', () => {
    listState = { error: new Error('boom') }
    show()
    expect(screen.getByRole('heading', { level: 1, name: 'API keys' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
    expect(screen.queryByText('No API keys yet')).toBeNull()
  })

  it('a sort in the address reaches the request', () => {
    show('?sort=-last_used_at')
    expect(seen.at(-1)?.sort).toBe('-last_used_at')
  })
})
