/**
 * The Findings list with quick views (research 234 D1): the metric strip and
 * the state tabs are gone; the sidebar carries the views and their counts, and
 * the page loads one stats response and one quick-views response.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen, fireEvent, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

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
const savedViewsState: { views: Array<Record<string, unknown>>; isLoading: boolean } = {
  views: [],
  isLoading: false,
}
vi.mock('@/features/saved-views/api/use-saved-views', async (orig) => ({
  ...(await orig<typeof import('@/features/saved-views/api/use-saved-views')>()),
  useSavedViews: () => ({
    views: savedViewsState.views,
    error: undefined,
    isLoading: savedViewsState.isLoading,
    mutate: vi.fn(),
  }),
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
vi.mock('@/features/saved-views/components/saved-views-menu', async (orig) => ({
  ...(await orig<typeof import('@/features/saved-views/components/saved-views-menu')>()),
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
  savedViewsState.views = []
  savedViewsState.isLoading = false
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
    // The overview numbers: one key. The practice's own total (asked only when
    // the list comes back empty with nothing narrowing it) adds the practice
    // condition and nothing else.
    const practiceKey = (f: Record<string, unknown> | undefined) =>
      !!f && ('practice' in f || 'practice_not' in f)
    const overview = statsCalls.filter((f) => !practiceKey(f))
    const keys = new Set(overview.map((f) => JSON.stringify(f)))
    expect(keys.size).toBe(1)
    for (const f of statsCalls) expect(JSON.stringify(f)).not.toMatch(/critical|login/)
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

  const row = () => screen.getByTestId('findings-toolbar-primary')
  const title = () => screen.getByTestId('findings-view-title')
  const modified = () => row().querySelector('[data-slot="list-modified"]')
  // Save view is one menu button: Save view (or Save changes) and Reset.
  const resetView = async () => {
    await userEvent.click(row().querySelector<HTMLElement>('[data-slot="list-view-save"]')!)
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Reset' }))
  }
  const QUICK = [
    { key: 'active', count: 12, params: 'state=open' },
    { key: 'needs_triage', count: 3, params: 'status=new' },
  ]

  it('a plain list is the Active view, unchanged: no Modified, Save view or Reset', () => {
    quickViewsState.views = QUICK
    openAt('')
    render(<FindingsPage />)
    expect(title()).toHaveTextContent('Active')
    expect(row()).toHaveAttribute('data-slot', 'list-title-row')
    expect(modified()).toBeNull()
    expect(row().querySelector('[data-slot="list-view-save"]')).toBeNull()
    expect(row().querySelector('[data-slot="list-view-reset"]')).toBeNull()
  })

  it('a view plus a filter keeps the view name and shows Modified, then one Save view menu', async () => {
    quickViewsState.views = QUICK
    openAt('?severity=high&practice=secrets')
    render(<FindingsPage />)
    expect(title()).toHaveTextContent('Active')
    expect(title()).not.toHaveTextContent(/custom view|saved view/i)
    expect(modified()).toHaveTextContent('Modified')
    // Modified comes right after the count, then the one Save view menu
    // (Reset is in it, not a second button).
    const start = row().querySelector('[data-slot="list-title-start"]')!
    const order = Array.from(
      start.querySelectorAll(
        '[data-slot="list-count"], [data-slot="list-modified"], [data-slot="list-view-save"], [data-slot="list-view-reset"]'
      )
    ).map((el) => el.getAttribute('data-slot'))
    expect(order).toEqual(['list-count', 'list-modified', 'list-view-save'])
    // Reset goes back to exactly the base view (the practice is its scope).
    await resetView()
    expect(params().toString()).toBe('state=open&practice=secrets')
  })

  it('a URL no view holds is All findings, modified; Reset opens every state', async () => {
    quickViewsState.views = QUICK
    openAt('?state=fixed&severity=high')
    render(<FindingsPage />)
    expect(title()).toHaveTextContent('All findings')
    expect(modified()).not.toBeNull()
    await resetView()
    expect(params().toString()).toBe('state=all')
  })

  it('a saved view is named by its own name, and never as "Saved view"', () => {
    const id = '019feab9-1111-7222-8333-444455556666'
    savedViewsState.views = [
      { id, name: 'Internet-facing criticals', page: 'findings', filter: {}, is_owner: true },
    ]
    openAt(`?view=${id}`)
    const { unmount } = render(<FindingsPage />)
    expect(title()).toHaveTextContent('Internet-facing criticals')
    expect(modified()).toBeNull()
    unmount()
    // Still loading: no name yet, rather than another view's.
    savedViewsState.views = []
    savedViewsState.isLoading = true
    openAt(`?view=${id}`)
    render(<FindingsPage />)
    expect(title()).toHaveTextContent('Loading…')
    expect(title()).not.toHaveTextContent('Internet-facing criticals')
    expect(modified()).toBeNull()
    // The row holds its end controls already: it keeps its shape when the
    // name arrives.
    expect(row().querySelector('[data-slot="list-title-end"]')).not.toBeNull()
  })

  it('the chips row no longer offers Reset to view', () => {
    quickViewsState.views = QUICK
    openAt('?severity=high&source=pentest')
    render(<FindingsPage />)
    expect(screen.queryByRole('button', { name: /reset to view/i })).toBeNull()
  })

  it('opens the Closed quick view with state=closed', () => {
    openAt('?state=closed')
    render(<FindingsPage />)
    expect(lastListFilters().state).toBe('closed')
  })

  it('runs the Pending approval and Accepted, expiring params', () => {
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

  // On a phone the toolbar's start goes into the Filters sheet: the queue's
  // name and the way back used to sit there, so the phone showed only a
  // Filters and a Refresh button. They are the view's title row now.
  it('gives the queue a title row with the way back, outside the toolbar', () => {
    openAt('?view=verify')
    render(<FindingsPage />)
    const row = screen.getByTestId('findings-verify-title-row')
    expect(within(row).getByTestId('findings-view-title')).toHaveTextContent(
      'Fixes awaiting verification'
    )
    fireEvent.click(within(row).getByRole('button', { name: 'All findings' }))
    expect(params().get('view')).toBeNull()
    expect(row.closest('[data-slot="list-toolbar"]')).toBeNull()
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
