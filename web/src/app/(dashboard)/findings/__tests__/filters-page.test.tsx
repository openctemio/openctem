/**
 * The Findings list's filters: chips for every active filter, filters the page
 * does not draw itself go to the API as they are, the filter contract is
 * fetched only when something needs it, and an unknown param is shown (and
 * kept out of the request once the contract is known).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen, fireEvent, within } from '@testing-library/react'

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
  useFindingApi: () => ({ data: undefined }),
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
        awaiting_verification: 3,
      },
      isLoading: false,
      mutate: vi.fn(),
    }
  },
  buildFindingsExportUrl: () => '#',
  invalidateFindingsCache: vi.fn(),
}))

const sourcesCalls: boolean[] = []
const quickViewsState: { views: Array<{ key: string; count: number; params: string }> } = {
  views: [],
}
const contractState: {
  contract: import('@/features/findings/filters/model').FilterContract | undefined
  asked: boolean[]
} = { contract: undefined, asked: [] }
vi.mock('@/features/findings/filters/contract', async (orig) => ({
  ...(await orig<typeof import('@/features/findings/filters/contract')>()),
  useFindingFilterContract: (enabled: boolean) => {
    contractState.asked.push(enabled)
    return { contract: contractState.contract, isLoading: false, error: undefined }
  },
}))
vi.mock('@/features/saved-views/api/use-saved-views', async (orig) => ({
  ...(await orig<typeof import('@/features/saved-views/api/use-saved-views')>()),
  useSavedViews: () => ({ views: [], error: undefined, isLoading: false, mutate: vi.fn() }),
}))

vi.mock('@/features/findings/api/use-quick-views', () => ({
  useFindingQuickViews: () => ({ data: { views: quickViewsState.views } }),
  refreshFindingQuickViews: vi.fn(),
}))
vi.mock('@/features/config/api/finding-source-api', () => ({
  useFindingSourcesApi: (_config?: unknown, enabled = true) => {
    sourcesCalls.push(enabled)
    return { data: undefined }
  },
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
vi.mock('@/features/remediation-hub/components/add-findings-to-task-dialog', () => ({
  AddFindingsToTaskDialog: () => null,
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
  sourcesCalls.length = 0
  quickViewsState.views = []
  contractState.contract = undefined
  contractState.asked.length = 0
})

const CONTRACT = {
  fields: [
    { name: 'severity', type: 'enum', ops: ['in', 'not_in'], enum: ['critical', 'high', 'low'] },
    { name: 'epss_score', type: 'number', ops: ['gte', 'gt', 'lte', 'lt'] },
    { name: 'network_port', type: 'integer', ops: ['in', 'not_in', 'gte', 'lte'] },
  ],
} as const

describe('Findings list filters', () => {
  it('asks for no filter contract when the URL holds only page-owned filters', () => {
    openAt('?severity=high&status=new&is_in_kev=true&pending_approval=true')
    render(<FindingsPage />)
    expect(contractState.asked.every((a) => a === false)).toBe(true)
  })

  it('draws a chip for each filter, facet ones included, with no contract', () => {
    openAt('?severity=high&status=new')
    render(<FindingsPage />)
    const bar = screen.getByTestId('findings-filter-bar')
    expect(within(bar).getByText('Severity is High')).toBeInTheDocument()
    expect(within(bar).getByText('Status is New')).toBeInTheDocument()
  })

  it('sends a filter the page does not draw itself, as it is, and asks for the contract', () => {
    openAt('?epss_score_gte=0.5&network_port=443,8443')
    render(<FindingsPage />)
    expect(contractState.asked.some((a) => a === true)).toBe(true)
    expect(lastListFilters().extra).toEqual({ epss_score_gte: '0.5', network_port: '443,8443' })
  })

  it('once the contract is known, an unknown param is shown and kept out of the request', () => {
    contractState.contract = CONTRACT as never
    openAt('?sevrity=high&epss_score_gte=0.5')
    render(<FindingsPage />)
    expect(lastListFilters().extra).toEqual({ epss_score_gte: '0.5' })
    expect(screen.getByTestId('filter-chip-unknown')).toHaveTextContent('Unknown filter “sevrity”')
    expect(screen.getByText('EPSS score ≥ 0.5')).toBeInTheDocument()
  })

  it('removing a chip removes only its param', () => {
    contractState.contract = CONTRACT as never
    openAt('?epss_score_gte=0.5&severity=high&page=2')
    render(<FindingsPage />)
    act(() => {
      fireEvent.click(screen.getByRole('button', { name: /remove filter epss score/i }))
    })
    expect(params().has('epss_score_gte')).toBe(false)
    expect(params().get('severity')).toBe('high')
    expect(params().has('page')).toBe(false)
  })

  it('counts the filters it does not draw in the clear action of the empty state', () => {
    openAt('?epss_score_gte=0.5')
    render(<FindingsPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(params().has('epss_score_gte')).toBe(false)
  })

  it('a filter change resets the selection scope (list asked on page 1)', () => {
    openAt('?page=3')
    render(<FindingsPage />)
    expect(lastListFilters().page).toBe(3)
    listCalls.length = 0
    act(() => {
      window.history.pushState(null, '', '/findings?page=3&epss_score_gte=0.5')
      window.dispatchEvent(new PopStateEvent('popstate'))
    })
    expect(listCalls.filter((f) => f.extra).every((f) => f.page === 1)).toBe(true)
  })
})
