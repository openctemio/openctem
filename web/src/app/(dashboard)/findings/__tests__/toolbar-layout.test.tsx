import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'

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

vi.mock('@/features/findings/api/use-findings-api', async (orig) => ({
  ...(await orig<typeof import('@/features/findings/api/use-findings-api')>()),
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

/**
 * The Findings toolbar is two fixed rows (guards the reported "search box
 * jumps under the filter button" bug):
 *   row 1 = state lens, then the page actions (refresh, export, task);
 *   row 2 = [filter | search] as one control, then saved views, Group, View.
 * Layout itself is measured by e2e/specs/21-findings-toolbar-layout.spec.ts;
 * this pins the structure that layout depends on.
 */

function renderAt(search = '') {
  window.history.replaceState(null, '', `/findings${search}`)
  return render(<FindingsPage />)
}

const follows = (a: Element, b: Element) =>
  Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING)

describe('Findings toolbar layout', () => {
  beforeEach(() => {
    listCalls.length = 0
    statsCalls.length = 0
  })

  it('puts the lens and the page actions in row 1, never in the table toolbar', () => {
    renderAt()
    const primary = screen.getByTestId('findings-toolbar-primary')
    const toolbar = screen.getByTestId('data-table-toolbar')
    const lens = screen.getByRole('radiogroup', { name: 'Finding state' })
    expect(primary.contains(lens)).toBe(true)
    expect(toolbar.contains(lens)).toBe(false)
    expect(follows(primary, toolbar)).toBe(true)

    const refresh = within(primary).getByRole('button', { name: 'Refresh' })
    const exportBtn = within(primary).getByRole('button', { name: 'Export' })
    const task = within(primary).getByRole('button', { name: /task from filters/i })
    // Tab order = visual order: lens, refresh, export, task.
    expect(follows(lens, refresh)).toBe(true)
    expect(follows(refresh, exportBtn)).toBe(true)
    expect(follows(exportBtn, task)).toBe(true)
    // The narrow fallback folds the same actions into one named menu.
    expect(within(primary).getByRole('button', { name: 'More actions' })).toBeInTheDocument()
  })

  it('joins the filter button and the search field into one control in row 2', () => {
    renderAt()
    const toolbar = screen.getByTestId('data-table-toolbar')
    const group = screen.getByTestId('findings-filter-search')
    expect(toolbar.contains(group)).toBe(true)
    const search = screen.getByRole('textbox', { name: 'Search findings' })
    expect(group.contains(search)).toBe(true)
    const filters = group.querySelectorAll('[data-slot="filter-button"]')
    expect(filters.length).toBeGreaterThan(0)
    filters.forEach((f) => expect(follows(f, search)).toBe(true))
    // One control: the group does not wrap, so the field cannot drop under the
    // button, and the field keeps a usable minimum width.
    expect(group.className).not.toMatch(/flex-wrap/)
    expect(search.parentElement?.className).toMatch(/min-w-40/)
    // Group and View come after the search, in the same row.
    const groupBy = within(toolbar).getByRole('combobox', { name: 'Group findings' })
    expect(follows(search, groupBy)).toBe(true)
  })

  it('the table toolbar is a size container, so labels follow the list width', () => {
    renderAt()
    expect(screen.getByTestId('data-table-toolbar').className).toMatch(/@container\/toolbar/)
    expect(screen.getByTestId('findings-toolbar-primary').className).toMatch(/@container\/actions/)
  })

  it('grouped view keeps the same two rows (lens in row 1, search in row 2)', () => {
    renderAt('?group=severity')
    const primary = screen.getByTestId('findings-toolbar-primary')
    expect(within(primary).getByRole('radiogroup', { name: 'Finding state' })).toBeInTheDocument()
    expect(within(primary).queryByRole('button', { name: 'Export' })).toBeNull()
    const toolbar = screen.getByTestId('data-table-toolbar')
    expect(within(toolbar).getByRole('textbox', { name: 'Search findings' })).toBeInTheDocument()
  })
})
