/**
 * The Findings state lens (research 24 P0-4, owner decision C2): Open, the
 * default, Fixed, Dispositioned, All. One URL param the API compiles to a
 * status set; counts come from by_state of the same filter.
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

vi.mock('@/features/findings/api/use-findings-api', () => ({
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
    return {
      data: {
        total: 18,
        by_severity: {},
        by_status: {},
        open_count: 12,
        by_state: { open: 12, fixed: 4, dispositioned: 2, all: 18 },
      },
      isLoading: false,
      mutate: vi.fn(),
    }
  },
  buildFindingsExportUrl: () => '#',
  invalidateFindingsCache: vi.fn(),
}))

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
const lastListFilters = () => listCalls[listCalls.length - 1]

beforeEach(() => {
  listCalls.length = 0
  statsCalls.length = 0
})

describe('Findings state lens', () => {
  it('lands on Open and asks the API for the open lens', () => {
    openAt('')
    render(<FindingsPage />)
    expect(screen.getByRole('radio', { name: /^Open/ })).toHaveAttribute('aria-checked', 'true')
    expect(lastListFilters().state).toBe('open')
    // Stats are asked under every lens at once (by_state), never per lens:
    // the overview strip is page-level (research/81).
    expect(statsCalls.every((f) => f?.state === 'all')).toBe(true)
  })

  it('shows honest lens counts from by_state of the same filter', () => {
    openAt('?severity=critical')
    render(<FindingsPage />)
    // The counts call carries the other filters, under every lens at once.
    expect(statsCalls.some((f) => f?.state === 'all')).toBe(true)
    expect(screen.getByRole('radio', { name: /^Fixed/ })).toHaveTextContent('4')
    expect(screen.getByRole('radio', { name: /^Dispositioned/ })).toHaveTextContent('2')
    expect(screen.getByRole('radio', { name: /^Open/ })).toHaveTextContent('12')
  })

  it('switching to Fixed puts state=fixed in the URL and the request, keeping other filters', () => {
    openAt('?severity=critical')
    render(<FindingsPage />)
    act(() => {
      fireEvent.click(screen.getByRole('radio', { name: /^Fixed/ }))
    })
    expect(params().get('state')).toBe('fixed')
    expect(params().get('severity')).toBe('critical')
    expect(lastListFilters().state).toBe('fixed')
    expect(screen.getByRole('radio', { name: /^Fixed/ })).toHaveAttribute('aria-checked', 'true')
  })

  it('keyboard arrows move the lens', () => {
    openAt('')
    render(<FindingsPage />)
    const open = screen.getByRole('radio', { name: /^Open/ })
    act(() => {
      fireEvent.keyDown(open, { key: 'ArrowRight' })
    })
    expect(params().get('state')).toBe('fixed')
  })

  it('an unknown lens in the URL falls back to Open', () => {
    openAt('?state=closed')
    render(<FindingsPage />)
    expect(lastListFilters().state).toBe('open')
  })

  it('does not lay the default lens over a saved view, but does an explicit one', () => {
    openAt('?view=019feab9-1111-7222-8333-444455556666')
    const { unmount } = render(<FindingsPage />)
    expect(lastListFilters().state).toBeUndefined()
    unmount()
    openAt('?view=019feab9-1111-7222-8333-444455556666&state=dispositioned')
    render(<FindingsPage />)
    expect(lastListFilters().state).toBe('dispositioned')
  })

  it('a filter change on page 3 asks page 1 at once, never the old page (research/81)', () => {
    openAt('?page=3')
    render(<FindingsPage />)
    expect(lastListFilters().page).toBe(3)
    listCalls.length = 0
    act(() => {
      fireEvent.click(screen.getByRole('radio', { name: /^Fixed/ }))
    })
    const fixed = listCalls.filter((f) => f.state === 'fixed')
    expect(fixed.length).toBeGreaterThan(0)
    expect(fixed.every((f) => f.page === 1)).toBe(true)
  })
})
