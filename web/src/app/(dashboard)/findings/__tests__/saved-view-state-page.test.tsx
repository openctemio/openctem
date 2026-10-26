/**
 * The Findings list's saved-view state and its primary action: columns and
 * density live in the URL and are saved with a view, Priority is always shown,
 * Severity starts hidden in the Active view, the unsaved-changes dot compares
 * the list with the open view, and Triage opens triage mode on the Needs
 * triage queue (or, with nothing to triage, the Needs triage view).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

Element.prototype.scrollIntoView ??= () => {}
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const listCalls: Array<Record<string, unknown>> = []
const listState: { rows: Array<Record<string, unknown>> } = { rows: [] }
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
  buildFindingsEndpoint: () => '/api/v1/findings',
  useFindingApi: () => ({ data: undefined }),
  useFindingsApi: (filters: Record<string, unknown>) => {
    listCalls.push(filters)
    return {
      data: { data: listState.rows, total: listState.rows.length, page: 1, per_page: 20 },
      isValidating: false,
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
const savedViews: { views: Array<Record<string, unknown>> } = { views: [] }
vi.mock('@/features/saved-views/api/use-saved-views', async (orig) => ({
  ...(await orig<typeof import('@/features/saved-views/api/use-saved-views')>()),
  useSavedViews: () => ({
    views: savedViews.views,
    error: undefined,
    isLoading: false,
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

const denied = new Set<string>()
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => !denied.has(p) }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useMyGroups: () => ({ groups: [] }),
}))
vi.mock('@/features/findings/components/lifecycle/finding-sub-status', () => ({
  FindingSubStatus: () => null,
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

beforeEach(() => {
  denied.clear()
  listCalls.length = 0
  statsCalls.length = 0
  sourcesCalls.length = 0
  quickViewsState.views = []
  contractState.contract = undefined
  listState.rows = []
  savedViews.views = []
  contractState.asked.length = 0
  routerPush.mockClear()
  sessionStorage.clear()
})

const VIEW_ID = '019feab9-1111-7222-8333-444455556666'
const row = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  title: `finding ${id}`,
  severity: 'high',
  status: 'new',
  source: 'sast',
  asset_id: 'a1',
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
  ...extra,
})
const headers = () => screen.queryAllByRole('columnheader').map((h) => h.textContent?.trim())

describe('Findings columns', () => {
  it('Priority and Finding are always shown, even when no row has a priority', () => {
    listState.rows = [row('1')]
    openAt('')
    render(<FindingsPage />)
    expect(headers()).toContain('Priority')
    expect(headers()).toContain('Title')
  })

  it('Severity starts hidden in the Active view and shown in Needs triage', () => {
    listState.rows = [row('1')]
    openAt('')
    const { unmount } = render(<FindingsPage />)
    expect(headers()).not.toContain('Severity')
    unmount()
    openAt('?status=new&state=all')
    render(<FindingsPage />)
    expect(headers()).toContain('Severity')
  })

  it('the scanner and the first-seen date start hidden', () => {
    listState.rows = [row('1')]
    openAt('?status=new&state=all')
    render(<FindingsPage />)
    expect(headers()).not.toContain('Source')
    expect(headers()).not.toContain('Created')
  })

  it('a columns param shows exactly those optional columns', () => {
    listState.rows = [row('1')]
    openAt('?columns=source,createdAt')
    render(<FindingsPage />)
    expect(headers()).toEqual(expect.arrayContaining(['Source', 'Created', 'Priority', 'Title']))
    expect(headers()).not.toContain('Status')
  })

  it("a saved view's columns apply, and the URL beats them", () => {
    listState.rows = [row('1')]
    savedViews.views = [
      {
        id: VIEW_ID,
        name: 'Layout',
        is_owner: true,
        filter: { v: 1 },
        columns: ['title', 'priorityClass', 'source'],
        density: 'compact',
      },
    ]
    openAt(`?view=${VIEW_ID}`)
    const { unmount } = render(<FindingsPage />)
    expect(headers()).toContain('Source')
    expect(headers()).not.toContain('Status')
    unmount()
    openAt(`?view=${VIEW_ID}&columns=status`)
    render(<FindingsPage />)
    expect(headers()).toContain('Status')
    expect(headers()).not.toContain('Source')
  })

  it('hiding a column through the Display menu writes it to the URL; back to the default clears it', async () => {
    listState.rows = [row('1')]
    openAt('?status=new&state=all')
    render(<FindingsPage />)
    await userEvent.click(screen.getByRole('button', { name: /^display: density/i }))
    await userEvent.click(await screen.findByRole('menuitemcheckbox', { name: 'Severity' }))
    expect(params().get('columns')).toBe('asset,status,slaStatus')
    await userEvent.click(screen.getByRole('button', { name: /^display: density/i }))
    await userEvent.click(await screen.findByRole('menuitemcheckbox', { name: 'Severity' }))
    expect(params().has('columns')).toBe(false)
  })
})

describe('Findings unsaved-changes dot', () => {
  beforeEach(() => {
    savedViews.views = [
      {
        id: VIEW_ID,
        name: 'Crown jewels',
        is_owner: true,
        filter: { v: 1, filter: { all: [{ field: 'severity', op: 'in', value: ['critical'] }] } },
        density: 'compact',
      },
    ]
  })

  it('no dot for the view as opened', () => {
    openAt(`?view=${VIEW_ID}`)
    render(<FindingsPage />)
    expect(screen.queryByTestId('saved-view-dirty-dot')).toBeNull()
  })

  it('a dot for a filter on top, a changed column or a density', () => {
    for (const q of [
      `?view=${VIEW_ID}&epss_score_gte=0.5`,
      `?view=${VIEW_ID}&columns=source`,
      `?view=${VIEW_ID}&density=comfortable`,
    ]) {
      openAt(q)
      const { unmount } = render(<FindingsPage />)
      expect(screen.getByTestId('saved-view-dirty-dot'), q).toBeInTheDocument()
      unmount()
    }
  })

  it("the view's own filter repeated in the URL is no change", () => {
    openAt(`?view=${VIEW_ID}&severity=critical`)
    render(<FindingsPage />)
    expect(screen.queryByTestId('saved-view-dirty-dot')).toBeNull()
  })
})

describe('Findings Triage', () => {
  it('is not offered to someone who may not change a status', () => {
    denied.add('findings:status')
    quickViewsState.views = [{ key: 'needs_triage', count: 86, params: 'status=new' }]
    openAt('')
    render(<FindingsPage />)
    expect(screen.queryByRole('button', { name: /^Triage/ })).toBeNull()
  })

  it('is the primary button, with the Needs triage count', () => {
    quickViewsState.views = [{ key: 'needs_triage', count: 86, params: 'status=new' }]
    openAt('')
    render(<FindingsPage />)
    const button = screen.getByRole('button', { name: /^Triage/ })
    expect(button).toHaveTextContent('86')
    expect(button.getAttribute('data-variant') ?? button.className).toMatch(/default|bg-primary/)
  })

  it('turns secondary, "Triage view", with nothing to triage', () => {
    quickViewsState.views = [{ key: 'needs_triage', count: 0, params: 'status=new' }]
    openAt('')
    render(<FindingsPage />)
    const button = screen.getByRole('button', { name: /Triage view/ })
    expect(screen.queryByTestId('triage-count')).toBeNull()
    expect(button.className).not.toMatch(/bg-primary /)
  })

  it('opens triage mode on the Needs triage queue and remembers the list', () => {
    quickViewsState.views = [{ key: 'needs_triage', count: 3, params: 'status=new' }]
    openAt('?severity=critical')
    render(<FindingsPage />)
    act(() => {
      fireEvent.click(screen.getByRole('button', { name: /^Triage/ }))
    })
    expect(routerPush).toHaveBeenCalledWith('/findings/triage?status=new')
    const stored = JSON.parse(sessionStorage.getItem('openctem.findings.triage') ?? '{}')
    expect(stored.query).toBe('status=new')
    expect(stored.returnTo).toBe('/findings?severity=critical')
    expect(stored.fromList).toBe(true)
    expect(stored.viewKey).toBe('needs_triage')
  })

  it('opens the Needs triage view when nothing waits', () => {
    quickViewsState.views = [{ key: 'needs_triage', count: 0, params: 'status=new' }]
    openAt('')
    render(<FindingsPage />)
    act(() => {
      fireEvent.click(screen.getByRole('button', { name: /Triage view/ }))
    })
    expect(routerPush).not.toHaveBeenCalledWith(expect.stringContaining('/findings/triage'))
    expect(params().get('status')).toBe('new')
    expect(params().get('state')).toBe('all')
  })

  it('the t key does the same, but not while typing', () => {
    quickViewsState.views = [{ key: 'needs_triage', count: 3, params: 'status=new' }]
    openAt('')
    render(<FindingsPage />)
    const search = screen.getByRole('searchbox', { name: /search findings/i })
    search.focus()
    fireEvent.keyDown(search, { key: 't' })
    expect(routerPush).not.toHaveBeenCalledWith('/findings/triage?status=new')
    search.blur()
    act(() => {
      fireEvent.keyDown(document.body, { key: 't' })
    })
    expect(routerPush).toHaveBeenCalledWith('/findings/triage?status=new')
  })

  it('Add is a menu of Add finding and Import results', async () => {
    openAt('')
    render(<FindingsPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByRole('menuitem', { name: 'Add finding' })).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Import results' })).toBeInTheDocument()
  })
})
