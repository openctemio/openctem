import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const listCalls: Array<Record<string, unknown>> = []
const listState: { data?: unknown; error?: unknown } = {}

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
  useCredentialsApi: (filters: Record<string, unknown>) => {
    listCalls.push(filters)
    return { ...listState, isLoading: false, mutate: vi.fn() }
  },
  useCredentialIdentitiesApi: () => ({ data: undefined, isLoading: false }),
  useCredentialStatsApi: () => ({
    data: { total: 250, by_state: { active: 200, resolved: 50 }, by_severity: {} },
    isLoading: false,
  }),
  useCredentialEnumsApi: () => ({ data: { source_types: ['data_breach', 'dark_web'] } }),
  useRelatedCredentialsApi: () => ({ data: [], isLoading: false, mutate: vi.fn() }),
  useRevealCredentialApi: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateCredentialsCache: vi.fn(),
}))

import CredentialsPage from '../page'

const item = (severity: string) => ({
  id: 'c1',
  identifier: 'a@example.com',
  credential_type: 'password',
  source: 'data_breach',
  severity,
  state: 'active',
  first_seen_at: '2026-01-02T00:00:00Z',
  details: { breach_date: '2020-05-01' },
})

beforeEach(() => {
  listCalls.length = 0
  listState.data = undefined
  listState.error = undefined
  window.history.replaceState(
    {},
    '',
    '/credentials?page=3&per_page=50&sort=-severity&source=dark_web'
  )
})

describe('credentials page', () => {
  it('sends page, size, sort and source to the API and shows the server total', () => {
    listState.data = { items: [item('low')], total: 250, page: 3, total_pages: 5 }
    render(<CredentialsPage />)
    const last = listCalls[listCalls.length - 1]
    expect(last).toMatchObject({
      page: 3,
      per_page: 50,
      sort: '-severity',
      source: ['dark_web'],
    })
    expect(screen.getByText(/of 250/i)).toBeInTheDocument()
  })

  it('shows the severity as returned and the breach date, not an invented mapping', () => {
    listState.data = { items: [item('low')], total: 1 }
    render(<CredentialsPage />)
    expect(screen.getByText('Low')).toBeInTheDocument()
    // "Critical" is only the metric strip's label, never a severity badge on the row.
    expect(
      screen.queryByText('Critical', { selector: 'span:not([data-slot="metric-label"])' })
    ).not.toBeInTheDocument()
    expect(screen.queryByText('Classification')).not.toBeInTheDocument()
    expect(screen.getByText('Discovered')).toBeInTheDocument()
    expect(screen.getByText(new Date('2020-05-01').toLocaleDateString('en'))).toBeInTheDocument()
  })

  it('has no Pending status option', () => {
    listState.data = { items: [], total: 0 }
    render(<CredentialsPage />)
    expect(screen.queryByText(/pending/i)).not.toBeInTheDocument()
  })

  it('shows an error state with retry instead of an empty table', () => {
    listState.error = new Error('boom')
    render(<CredentialsPage />)
    expect(screen.getByText(/failed to load credential leaks/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
    expect(screen.queryByText('No credential leaks found')).not.toBeInTheDocument()
  })
})
