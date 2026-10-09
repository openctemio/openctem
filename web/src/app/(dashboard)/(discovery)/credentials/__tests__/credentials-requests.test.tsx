/**
 * The credentials page asks only for what it shows (research/81): the list in
 * the list view, the identities in the identity view, and its page-level
 * strip from GET /credentials/stats (not from the first 100 rows of a second
 * list request, which was wrong past 100).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const calls: { list: boolean[]; identities: boolean[]; stats: number } = {
  list: [],
  identities: [],
  stats: 0,
}

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/credentials',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))
vi.mock('@/features/credentials', async (orig) => ({
  ...(await orig<typeof import('@/features/credentials')>()),
  useCredentialsApi: (_f: unknown, _c: unknown, enabled = true) => {
    calls.list.push(enabled)
    return { data: { items: [], total: 0 }, isLoading: false, mutate: vi.fn() }
  },
  useCredentialIdentitiesApi: (_f: unknown, _c: unknown, enabled = true) => {
    calls.identities.push(enabled)
    return { data: { items: [], total: 0 }, isLoading: false }
  },
  useCredentialStatsApi: () => {
    calls.stats++
    return {
      data: {
        total: 250,
        by_state: { active: 180, resolved: 40, accepted: 20, false_positive: 10 },
        by_severity: { critical: 120 },
      },
      isLoading: false,
    }
  },
  useRelatedCredentialsApi: () => ({ data: undefined, isLoading: false }),
}))

import CredentialsPage from '../page'

beforeEach(() => {
  calls.list = []
  calls.identities = []
  calls.stats = 0
})

describe('Credentials page requests', () => {
  it('list view: loads the list and the stats, not the identities', () => {
    window.history.replaceState(null, '', '/credentials')
    render(<CredentialsPage />)
    expect(calls.list.at(-1)).toBe(true)
    expect(calls.identities.at(-1)).toBe(false)
    expect(calls.stats).toBeGreaterThan(0)
  })

  it('identity view: loads the identities, not the list', () => {
    window.history.replaceState(null, '', '/credentials?group=identity')
    render(<CredentialsPage />)
    expect(calls.identities.at(-1)).toBe(true)
    expect(calls.list.at(-1)).toBe(false)
  })

  it('the strip counts the whole set from the stats, past 100 rows', () => {
    window.history.replaceState(null, '', '/credentials')
    render(<CredentialsPage />)
    expect(screen.getAllByText('250').length).toBeGreaterThan(0)
    expect(screen.getAllByText('120').length).toBeGreaterThan(0)
  })
})
