/**
 * /exposures: the Closed tile equals the view it opens (resolved + accepted +
 * false positive), and a failed stats read says so instead of showing zeros.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/exposures',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))

const stats = vi.fn()
const rows = vi.hoisted(() => ({ current: [] as unknown[] }))
vi.mock('@/features/exposures/hooks', async (orig) => ({
  ...(await orig<typeof import('@/features/exposures/hooks')>()),
  useExposures: () => ({
    exposures: rows.current,
    total: rows.current.length,
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
  useExposureStats: () => stats(),
  useExposureHistory: () => ({ history: [], isLoading: false, error: undefined, mutate: vi.fn() }),
}))

import ExposuresPage from '../page'

const base = {
  total: 20,
  active_count: 5,
  resolved_count: 4,
  by_severity: {},
  by_state: { active: 5, resolved: 4, accepted: 3, false_positive: 2, in_review: 0 },
  by_event_type: {},
}

beforeEach(() => {
  stats.mockReset()
  rows.current = []
})

describe('/exposures stats', () => {
  it('Closed tile is resolved + accepted + false positive', () => {
    stats.mockReturnValue({ stats: base, isLoading: false, error: undefined, mutate: vi.fn() })
    render(<ExposuresPage />)
    expect(screen.queryByText('Resolved')).not.toBeInTheDocument()
    const tile = screen.getByRole('button', { name: /Closed/ })
    expect(tile).toHaveTextContent('9')
  })

  it('a failed stats read renders an error state with retry, not zeros', () => {
    stats.mockReturnValue({
      stats: { ...base, total: 0 },
      isLoading: false,
      error: new Error('boom'),
      mutate: vi.fn(),
    })
    render(<ExposuresPage />)
    expect(screen.getByText(/Couldn't load exposure statistics/i)).toBeInTheDocument()
  })
})

describe('/exposures list', () => {
  const exposure = {
    id: 'e1',
    title: 'Port 3389 open on gateway.example.com',
    event_type: 'port_open',
    severity: 'high',
    state: 'active',
    source: 'easm',
    description: 'Remote desktop is reachable from the internet',
    first_seen_at: '2026-10-01T00:00:00Z',
    last_seen_at: '2026-10-02T00:00:00Z',
  }

  it('names the view, says the count once and keeps one line per row', () => {
    stats.mockReturnValue({ stats: base, isLoading: false, error: undefined, mutate: vi.fn() })
    rows.current = [exposure]
    render(<ExposuresPage />)
    expect(screen.getByRole('heading', { level: 2, name: 'Needs attention' })).toBeInTheDocument()
    expect(document.querySelectorAll('[data-slot="list-count"]')).toHaveLength(1)
    // Unchanged view: no Modified mark, no Reset.
    expect(document.querySelector('[data-slot="list-modified"]')).toBeNull()
    expect(screen.getAllByRole('columnheader').map((h) => h.textContent?.trim())).toEqual([
      '',
      'Exposure',
      'Summary',
      'Signals',
      'Severity',
      'State',
      'Source',
      'First seen',
      'Actions',
    ])
    expect(screen.getByText('Remote desktop is reachable from the internet')).toHaveClass(
      'truncate'
    )
    // One filter entry (Add filter) and one fixed select (State); no filter menus.
    expect(screen.getByRole('button', { name: /Add filter/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'State: Needs attention' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Severity' })).toBeNull()
    expect(screen.getByRole('checkbox', { name: `Select ${exposure.title}` })).toBeInTheDocument()
  })

  it('an empty, unfiltered list is a first run: no toolbar', () => {
    stats.mockReturnValue({ stats: base, isLoading: false, error: undefined, mutate: vi.fn() })
    render(<ExposuresPage />)
    expect(screen.getByText('No exposures')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Add filter/ })).toBeNull()
  })
})
