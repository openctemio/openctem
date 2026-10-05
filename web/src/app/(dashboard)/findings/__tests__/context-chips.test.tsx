/**
 * The Findings list's deep-link context chips (owner report: the "Asset
 * 019feab9…" chip rendered as its own row above the table, pushing the table
 * down, and its X cleared every filter).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen, fireEvent } from '@testing-library/react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const ASSET_ID = '019feab9-1111-7222-8333-444455556666'
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
  useFindingsApi: () => ({
    data: { data: [], total: 0, page: 1, per_page: 20 },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useFindingStatsApi: () => ({
    data: { total: 0, by_severity: {}, by_status: {}, open_count: 0 },
    isLoading: false,
    mutate: vi.fn(),
  }),
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

// The label resolver: GET /assets/{id} through the tenant-gated hook.
const useAsset = vi.fn()
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAsset: (id: string | null) => useAsset(id),
}))
vi.mock('@/lib/api/scan-hooks', () => ({
  useScanSession: () => ({ data: undefined, isLoading: false }),
}))

import FindingsPage from '../page'

function openAt(search: string) {
  window.history.replaceState(null, '', `/findings${search}`)
}

beforeEach(() => {
  routerPush.mockReset()
  useAsset.mockReset()
  useAsset.mockReturnValue({
    asset: { id: ASSET_ID, name: 'payments-api.prod' },
    isLoading: false,
    error: undefined,
  })
})

describe('Findings context chips', () => {
  it('renders the asset chip inside the table toolbar, beside the search box', () => {
    openAt(`?asset_id=${ASSET_ID}&status=new,confirmed`)
    render(<FindingsPage />)

    const chip = screen.getByTestId('context-chip-asset_id')
    const search = screen.getByLabelText('Search findings')
    // Same toolbar group as the search box: the chips list is a sibling of the
    // search box's wrapper, not a row of its own above the table.
    const chipList = screen.getByTestId('context-filter-chips')
    expect(chipList.contains(chip)).toBe(true)
    expect(chipList.parentElement).toBe(search.parentElement?.parentElement)
  })

  it('shows the asset name, not the raw id', () => {
    openAt(`?asset_id=${ASSET_ID}`)
    render(<FindingsPage />)
    expect(screen.getByTestId('context-chip-asset_id-label')).toHaveTextContent('payments-api.prod')
    expect(screen.queryByText(new RegExp(`${ASSET_ID.slice(0, 8)}…`))).toBeNull()
  })

  it('X removes only the asset filter and keeps the other filters', () => {
    openAt(`?asset_id=${ASSET_ID}&status=new,confirmed&severity=critical`)
    render(<FindingsPage />)

    act(() => {
      fireEvent.click(
        screen.getByRole('button', { name: 'Remove asset filter: payments-api.prod' })
      )
    })

    const params = new URLSearchParams(window.location.search)
    expect(params.get('asset_id')).toBeNull()
    expect(params.get('status')).toBe('new,confirmed')
    expect(params.get('severity')).toBe('critical')
    expect(routerPush).not.toHaveBeenCalled()
    expect(screen.queryByTestId('context-chip-asset_id')).toBeNull()
  })

  it('shows "Unknown asset" when the asset is not visible to the caller', () => {
    useAsset.mockReturnValue({
      asset: null,
      isLoading: false,
      error: Object.assign(new Error('Not found'), { statusCode: 404 }),
    })
    openAt(`?asset_id=${ASSET_ID}`)
    render(<FindingsPage />)
    expect(screen.getByTestId('context-chip-asset_id-label')).toHaveTextContent('Unknown asset')
  })

  it('renders no chips list without a context parameter', () => {
    openAt('?status=new')
    render(<FindingsPage />)
    expect(screen.queryByTestId('context-filter-chips')).toBeNull()
  })
})
