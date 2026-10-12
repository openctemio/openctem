/**
 * The findings overview strip (research/81, owner design 2026-10-08): page-level
 * numbers that do not move with the state tab, search or filters, read from
 * ONE stats response; tab counts follow the filter; switching tabs sends no
 * stats request; each card applies the filter it counts.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen, fireEvent } from '@testing-library/react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const listCalls: Array<Record<string, unknown>> = []
const statsCalls: Array<Record<string, unknown> | undefined> = []
const routerPush = vi.fn()

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: routerPush, replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/findings',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))

vi.mock('swr', () => ({
  default: vi.fn(() => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() })),
  mutate: vi.fn(),
  useSWRConfig: () => ({ mutate: vi.fn() }),
}))

const OVERVIEW = {
  total: 96,
  by_severity: {},
  by_status: {},
  open_count: 89,
  by_state: { open: 89, fixed: 3, dispositioned: 4, all: 96 },
  open_by_severity: { critical: 7, high: 20, medium: 30, low: 20, info: 12 },
  kev_open: 5,
  sla_breached: 11,
  awaiting_verification: 2,
}
const FILTERED = {
  ...OVERVIEW,
  total: 9,
  by_state: { open: 7, fixed: 1, dispositioned: 1, all: 9 },
  open_by_severity: { critical: 7 },
  kev_open: 1,
  sla_breached: 2,
  awaiting_verification: 0,
}

vi.mock('@/features/findings/api/use-findings-api', async (orig) => {
  const actual = await orig<typeof import('@/features/findings/api/use-findings-api')>()
  return {
    buildFindingStatsUrl: actual.buildFindingStatsUrl,
    useFindingsApi: (filters: Record<string, unknown>) => {
      listCalls.push(filters)
      return {
        data: { data: [], total: 0, page: 1, per_page: 20 },
        error: undefined,
        isLoading: false,
        mutate: vi.fn(),
      }
    },
    useFindingStatsApi: (filters?: Record<string, unknown>) => {
      statsCalls.push(filters)
      const url = actual.buildFindingStatsUrl(filters as never)
      return {
        data: url.includes('severity=') || url.includes('q=') ? FILTERED : OVERVIEW,
        isLoading: false,
        mutate: vi.fn(),
      }
    },
    buildFindingsExportUrl: () => '#',
    invalidateFindingsCache: vi.fn(),
  }
})

vi.mock('@/features/config/api/finding-source-api', () => ({
  useFindingSourcesApi: () => ({ data: undefined }),
  groupFindingSourcesByCategory: () => [],
}))

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
vi.mock('@/features/saved-views/components/saved-views-menu', () => ({
  SavedViewsMenu: () => null,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

// Dialogs and drawers are closed and have their own data stacks.
vi.mock('@/features/findings/components/auto-assign-dialog', () => ({
  AutoAssignDialog: () => null,
}))
vi.mock('@/features/findings/components/mark-fixed-dialog', () => ({ MarkFixedDialog: () => null }))
vi.mock('@/features/findings/components/create-ticket-dialog', () => ({
  CreateTicketDialog: () => null,
}))
vi.mock('@/features/remediation/components/link-findings-dialog', () => ({
  LinkFindingsToRemediationDialog: () => null,
}))
vi.mock('@/features/findings', async (orig) => ({
  ...(await orig<typeof import('@/features/findings')>()),
  FindingDetailDrawer: () => null,
  CreateFindingDialog: () => null,
}))

vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAsset: () => ({ asset: null, isLoading: false, error: undefined }),
}))

import FindingsPage from '../page'

function openAt(search: string) {
  window.history.replaceState(null, '', `/findings${search}`)
}
const params = () => new URLSearchParams(window.location.search)

beforeEach(() => {
  listCalls.length = 0
  statsCalls.length = 0
})

import { buildFindingStatsUrl } from '@/features/findings/api/use-findings-api'

const statsUrls = () => new Set(statsCalls.map((f) => buildFindingStatsUrl(f as never)))
const card = (label: RegExp) => screen.getByRole('button', { name: label })

describe('Findings overview strip', () => {
  it('loads ONE stats response when no filter is set', () => {
    openAt('')
    render(<FindingsPage />)
    expect(statsUrls().size).toBe(1)
    const [url] = [...statsUrls()]
    expect(url).toContain('state=all')
  })

  it('shows page-level numbers that agree with the tab counts', () => {
    openAt('')
    render(<FindingsPage />)
    expect(card(/^Total/)).toHaveTextContent('96')
    expect(screen.getByRole('radio', { name: /^All/ })).toHaveTextContent('96')
    expect(card(/^Open/)).toHaveTextContent('89')
    expect(screen.getByRole('radio', { name: /^Open/ })).toHaveTextContent('89')
    expect(card(/^Critical open/)).toHaveTextContent('7')
    expect(card(/^High open/)).toHaveTextContent('20')
    expect(card(/^Overdue SLA/)).toHaveTextContent('11')
    expect(card(/^In CISA KEV/)).toHaveTextContent('5')
    expect(card(/^Awaiting verification/)).toHaveTextContent('2')
  })

  it('switching tabs keeps the strip and sends no new stats request', () => {
    openAt('')
    render(<FindingsPage />)
    const before = statsUrls()
    act(() => {
      fireEvent.click(screen.getByRole('radio', { name: /^Fixed/ }))
    })
    expect(params().get('state')).toBe('fixed')
    expect(statsUrls()).toEqual(before)
    expect(card(/^Total/)).toHaveTextContent('96')
    expect(card(/^Critical open/)).toHaveTextContent('7')
  })

  it('a filter changes the tab counts, never the strip', () => {
    openAt('?severity=low')
    render(<FindingsPage />)
    // Two responses now: the page-level overview and the filtered tab counts.
    expect(statsUrls().size).toBe(2)
    expect(screen.getByRole('radio', { name: /^All/ })).toHaveTextContent('9')
    expect(card(/^Total/)).toHaveTextContent('96')
    expect(card(/^Open/)).toHaveTextContent('89')
  })

  it('a card applies the filter it counts, shows as active, and clears on a second click', () => {
    openAt('?state=fixed')
    render(<FindingsPage />)
    act(() => {
      fireEvent.click(card(/^Critical open/))
    })
    expect(params().get('state') ?? 'open').toBe('open')
    expect(params().get('severity')).toBe('critical')
    expect(card(/^Critical open/)).toHaveAttribute('aria-pressed', 'true')
    act(() => {
      fireEvent.click(card(/^Critical open/))
    })
    expect(params().get('severity')).toBeNull()
    expect(card(/^Critical open/)).toHaveAttribute('aria-pressed', 'false')
  })

  it('each card says what it counts', () => {
    openAt('')
    render(<FindingsPage />)
    expect(card(/^Overdue SLA/)).toHaveAttribute('title', expect.stringContaining('SLA policy'))
    expect(card(/^Total/)).toHaveAttribute('title', expect.stringContaining('All tab'))
  })
})
