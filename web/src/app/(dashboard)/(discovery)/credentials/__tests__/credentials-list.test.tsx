/**
 * /credentials on the shared list pattern: several values per filter reach
 * the API as lists, each filter in use is a removable chip, the count is said
 * once, Reset goes back to the list as it opens, the identity grouping keeps
 * only the filters its endpoint takes, and the phone card has fixed slots
 * with the secret never on it.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import type { CredentialLeakRow } from '@/features/credentials/lib'
import { CredentialPhoneCard } from '@/features/credentials/components/credential-list-parts'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const listCalls: Array<Record<string, unknown>> = []
const identityCalls: Array<Record<string, unknown>> = []

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/credentials',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { CredentialsWrite: 'w', CredentialsReveal: 'r' },
  usePermissions: () => ({ can: () => true }),
  useHasPermission: () => true,
}))
vi.mock('@/features/assets', () => ({
  AssetDetailSheet: () => null,
  StatCard: () => null,
  StatsGrid: () => null,
  MetadataGrid: () => null,
  MetadataRow: () => null,
  SectionTitle: () => null,
}))
vi.mock('@/features/credentials/api/use-credentials-api', () => ({
  buildCredentialsEndpoint: () => '/x',
  useCredentialsApi: (filters: Record<string, unknown>, _c: unknown, enabled = true) => {
    if (enabled) listCalls.push(filters)
    return {
      data: {
        items: [
          {
            id: 'c1',
            identifier: 'alice@example.com',
            credential_type: 'api_key',
            source: 'dark_web',
            severity: 'high',
            state: 'active',
            first_seen_at: '2026-01-02T00:00:00Z',
            secret_masked: 'sk-****9f',
            has_secret: true,
          },
        ],
        total: 250,
      },
      isLoading: false,
      mutate: vi.fn(),
    }
  },
  useCredentialIdentitiesApi: (filters: Record<string, unknown>, _c: unknown, enabled = true) => {
    if (enabled) identityCalls.push(filters)
    return {
      data: {
        items: [
          { identity: 'alice@example.com', identity_type: 'email', exposure_count: 2 },
          { identity: 'bob', identity_type: 'username', exposure_count: 1 },
        ],
        total: 2,
      },
      isLoading: false,
      mutate: vi.fn(),
    }
  },
  useCredentialStatsApi: () => ({
    data: { total: 250, by_state: { active: 200, resolved: 50 }, by_severity: { high: 7 } },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useCredentialEnumsApi: () => ({ data: { source_types: ['data_breach', 'dark_web'] } }),
  useRelatedCredentialsApi: () => ({ data: [], isLoading: false, mutate: vi.fn() }),
  useRevealCredentialApi: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateCredentialsCache: vi.fn(),
}))
vi.mock('@/lib/api/client', () => ({
  get: vi.fn(async () => ({ items: [], total: 0 })),
  post: vi.fn(),
}))

import CredentialsPage from '../page'

beforeEach(() => {
  listCalls.length = 0
  identityCalls.length = 0
})

const titleRow = () => screen.getByTestId('credentials-title-row')

describe('credentials list', () => {
  it('sends several statuses, severities and sources as lists and shows one chip per filter', () => {
    window.history.replaceState(
      {},
      '',
      '/credentials?status=active,inactive&severity=critical,medium&source=dark_web,data_breach'
    )
    render(<CredentialsPage />)
    expect(listCalls.at(-1)).toMatchObject({
      state: ['active', 'accepted', 'false_positive'],
      severity: ['critical', 'medium'],
      source: ['dark_web', 'data_breach'],
    })
    const chips = screen.getByTestId('credential-filter-chips')
    expect(within(chips).getByText('Status: Active, Inactive')).toBeInTheDocument()
    expect(within(chips).getByText('Severity: Critical, Medium')).toBeInTheDocument()
    expect(within(chips).getByText('Source: Dark web, Data breach')).toBeInTheDocument()
  })

  it('drops a value the list does not know instead of sending it', () => {
    window.history.replaceState({}, '', '/credentials?status=all&severity=bogus&source=all')
    render(<CredentialsPage />)
    expect(listCalls.at(-1)).toMatchObject({
      state: undefined,
      severity: undefined,
      source: undefined,
    })
    expect(screen.queryByTestId('credential-filter-chips')).not.toBeInTheDocument()
  })

  it('says the count once, in the title row', () => {
    window.history.replaceState({}, '', '/credentials')
    render(<CredentialsPage />)
    expect(within(titleRow()).getByText('250 leaks')).toBeInTheDocument()
    expect(screen.getAllByText('250 leaks')).toHaveLength(1)
  })

  it('Reset goes back to the list as it opens and keeps the page size', () => {
    window.history.replaceState(
      {},
      '',
      '/credentials?status=active&q=alice&sort=-severity&group=identity&per_page=50'
    )
    render(<CredentialsPage />)
    fireEvent.click(within(titleRow()).getByRole('button', { name: 'Reset' }))
    expect(window.location.search).toBe('?per_page=50')
  })

  it('grouped by identity: counts identities and keeps only the status filter', () => {
    window.history.replaceState(
      {},
      '',
      '/credentials?group=identity&status=active&source=dark_web&severity=high'
    )
    render(<CredentialsPage />)
    expect(listCalls).toHaveLength(0)
    expect(identityCalls.at(-1)).toMatchObject({ state: ['active'] })
    expect(within(titleRow()).getByText('2 identities')).toBeInTheDocument()
    const chips = screen.getByTestId('credential-filter-chips')
    expect(within(chips).getByText('Status: Active')).toBeInTheDocument()
    expect(within(chips).queryByText(/Source:/)).not.toBeInTheDocument()
    expect(within(chips).queryByText(/Severity:/)).not.toBeInTheDocument()
  })

  it('a metric tile sets its filter alone', () => {
    window.history.replaceState({}, '', '/credentials?severity=critical,medium')
    render(<CredentialsPage />)
    fireEvent.click(screen.getByRole('button', { name: /^High/ }))
    expect(new URLSearchParams(window.location.search).get('severity')).toBe('high')
  })
})

const leak = (over: Partial<CredentialLeakRow['metadata']> = {}, name = 'alice@example.com') =>
  ({
    id: 'c1',
    type: 'credential',
    name,
    status: 'active',
    firstSeen: '2026-01-02T00:00:00Z',
    metadata: {
      source: 'data_breach',
      username: 'alice',
      leakDate: '',
      severity: 'critical',
      hasSecret: true,
      secretMasked: 'pa****rd',
      credentialType: 'password',
      ...over,
    },
  }) as unknown as CredentialLeakRow

describe('credential phone card', () => {
  it('has the name, the severity, type and source, status and leak date; never the secret', () => {
    const recent = new Date(Date.now() - 3 * 86_400_000).toISOString().slice(0, 10)
    const { container } = render(
      <CredentialPhoneCard item={leak({ leakDate: recent })} onOpen={vi.fn()} />
    )
    expect(screen.getByText('alice@example.com')).toBeInTheDocument()
    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(screen.getByText(/Password, Data breach/)).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Recent')).toBeInTheDocument()
    expect(container.textContent).not.toContain('pa****rd')
  })

  it('without a leak date or a source it shows the discovery date and the type alone', () => {
    render(<CredentialPhoneCard item={leak({ source: '', username: '' })} onOpen={vi.fn()} />)
    expect(screen.getByText('Password')).toBeInTheDocument()
    expect(screen.getByText(/^Discovered /)).toBeInTheDocument()
    expect(screen.queryByText('Recent')).not.toBeInTheDocument()
  })

  it('a tap opens the leak', () => {
    const onOpen = vi.fn()
    render(<CredentialPhoneCard item={leak()} onOpen={onOpen} />)
    fireEvent.click(screen.getByText('alice@example.com'))
    expect(onOpen).toHaveBeenCalledOnce()
  })
})
