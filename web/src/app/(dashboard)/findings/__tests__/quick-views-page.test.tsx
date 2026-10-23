/**
 * The Findings list with quick views (research 234 D1): the metric strip and
 * the state tabs are gone; the sidebar carries the views and their counts, and
 * the page loads one stats response and one quick-views response.
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

vi.mock('@/features/findings/api/use-findings-api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/features/findings/api/use-findings-api')>()),
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
vi.mock('@/features/findings/filters/contract', async (orig) => ({
  ...(await orig<typeof import('@/features/findings/filters/contract')>()),
  useFindingFilterContract: () => ({ contract: undefined, isLoading: false, error: undefined }),
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
})

describe('Findings list with quick views', () => {
  it('has no metric strip and no state tabs', () => {
    openAt('')
    render(<FindingsPage />)
    expect(screen.queryByRole('radiogroup')).toBeNull()
    expect(screen.queryByText('Critical open')).toBeNull()
    expect(screen.queryByText('Overdue SLA')).toBeNull()
    expect(screen.queryByRole('button', { name: /^Total/ })).toBeNull()
  })

  it('lands on the Open lens', () => {
    openAt('')
    render(<FindingsPage />)
    expect(lastListFilters().state).toBe('open')
  })

  it('asks for one stats response whatever the filters are', () => {
    openAt('?severity=critical&q=login')
    render(<FindingsPage />)
    expect(statsCalls.every((f) => f?.state === 'all')).toBe(true)
    const keys = new Set(statsCalls.map((f) => JSON.stringify(f)))
    expect(keys.size).toBe(1)
    expect(JSON.stringify(statsCalls[0])).not.toContain('critical')
  })

  it('names the view in the header: the quick view the URL is', () => {
    quickViewsState.views = [
      { key: 'active', count: 12, params: 'state=open' },
      { key: 'needs_triage', count: 3, params: 'status=new' },
    ]
    openAt('?status=new&state=all')
    render(<FindingsPage />)
    expect(screen.getByTestId('findings-view-title')).toHaveTextContent('Needs triage')
  })

  it('a plain list is the Active view, and an unmatched combination is a custom view', () => {
    quickViewsState.views = [{ key: 'active', count: 12, params: 'state=open' }]
    openAt('')
    const { unmount } = render(<FindingsPage />)
    expect(screen.getByTestId('findings-view-title')).toHaveTextContent('Active')
    unmount()
    openAt('?severity=high')
    render(<FindingsPage />)
    expect(screen.getByTestId('findings-view-title')).toHaveTextContent('Custom view')
  })

  it('opens the Closed quick view with state=closed', () => {
    openAt('?state=closed')
    render(<FindingsPage />)
    expect(lastListFilters().state).toBe('closed')
  })

  it('runs the Pending approval and Accepted · expiring params', () => {
    openAt('?pending_approval=true&state=all')
    const { unmount } = render(<FindingsPage />)
    expect(lastListFilters().pending_approval).toBe(true)
    expect(lastListFilters().state).toBe('all')
    unmount()
    openAt('?status=accepted&acceptance_expires_at_lte=P30D&state=all')
    render(<FindingsPage />)
    expect(lastListFilters().acceptance_expires_at_lte).toBe('P30D')
    expect(lastListFilters().statuses).toEqual(['accepted'])
  })

  it('offers the verification queue where the old card was, only when something awaits', () => {
    openAt('')
    render(<FindingsPage />)
    fireEvent.click(screen.getByRole('button', { name: /awaiting verification/i }))
    expect(params().get('view')).toBe('verify')
  })

  it('opens the queue with a section for the claimed fixes that have no CVE', () => {
    openAt('?view=verify&asset_id=asset-1')
    render(<FindingsPage />)
    // The by-CVE groups leave a finding without a CVE out; this list holds
    // them, in the same scope as the count.
    const noCve = listCalls.find((f) => f.cve_id_unset === true)
    expect(noCve).toMatchObject({
      statuses: ['fix_applied'],
      asset_id: 'asset-1',
      extra: { source_not: 'pentest' },
    })
    expect(statsCalls.some((f) => f?.asset_id === 'asset-1')).toBe(true)
  })

  it('does not load the source catalog until the Source filter is opened', () => {
    openAt('')
    render(<FindingsPage />)
    expect(sourcesCalls.every((enabled) => enabled === false)).toBe(true)
  })

  it('loads the source catalog at once when a source is already picked', () => {
    openAt('?source=sast')
    render(<FindingsPage />)
    expect(sourcesCalls.every((enabled) => enabled === true)).toBe(true)
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
      window.history.pushState(null, '', '/findings?page=3&state=closed')
      window.dispatchEvent(new PopStateEvent('popstate'))
    })
    const closed = listCalls.filter((f) => f.state === 'closed')
    expect(closed.length).toBeGreaterThan(0)
    expect(closed.every((f) => f.page === 1)).toBe(true)
  })
})
