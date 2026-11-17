import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'

const state = vi.hoisted(() => ({
  isError: false,
  data: [] as unknown[],
  truncated: false,
  total: 0,
  refresh: vi.fn(),
  filters: undefined as unknown,
  bulkDelete: vi.fn(),
  search: '',
  can: true,
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/assets/groups',
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' }, isLoading: false }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => state.can }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/assets/components/assets-section-tabs', () => ({
  AssetsSectionTabs: () => null,
}))
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (key: string, fallback: string) => [
    key === 'q' ? state.search : fallback,
    (v: string) => {
      if (key === 'q') state.search = v
    },
  ],
  useUrlFilterList: () => [[], vi.fn()],
}))
vi.mock('@/features/assets', () => ({
  useAssets: () => ({ assets: [], total: 0, isLoading: false }),
}))
vi.mock('@/features/asset-groups', () => ({
  CreateGroupDialog: () => null,
  EditGroupDialog: () => null,
  GroupQuickView: () => null,
  useAllAssetGroups: (opts: { filters: unknown }) => {
    state.filters = opts.filters
    return {
      data: state.data,
      total: state.total,
      truncated: state.truncated,
      cap: 1000,
      isLoading: false,
      isError: state.isError,
      error: state.isError ? Object.assign(new Error('boom'), { statusCode: 500 }) : null,
      mutate: state.refresh,
    }
  },
  useGroupAssets: () => ({ data: [] }),
  useAssetGroupStats: () => ({
    data: { total: 3, byCriticality: {}, totalAssets: 0, averageRiskScore: 0 },
    isLoading: false,
  }),
  useCreateAssetGroup: () => ({ trigger: vi.fn() }),
  useUpdateAssetGroup: () => ({ trigger: vi.fn() }),
  useDeleteAssetGroup: () => ({ trigger: vi.fn() }),
  useAddAssetsToGroup: () => ({ trigger: vi.fn(), isMutating: false }),
  useBulkAssetGroupOperations: () => ({ bulkDelete: state.bulkDelete, bulkUpdate: vi.fn() }),
}))

import AssetGroupsPage from '../page'

beforeEach(() => {
  state.isError = false
  state.data = []
  state.truncated = false
  state.total = 0
  state.search = ''
  state.can = true
  state.refresh.mockReset()
  state.bulkDelete.mockReset()
})

const group = (id: string, name: string) => ({
  id,
  name,
  environment: 'production',
  criticality: 'high',
  assetCount: 0,
  findingCount: 0,
  riskScore: 0,
})

describe('/assets/groups', () => {
  it('a failed load shows an error with retry, not the empty state', () => {
    state.isError = true
    render(<AssetGroupsPage />)
    expect(screen.queryByText('No asset groups found')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(state.refresh).toHaveBeenCalled()
  })

  it('sends the search to the server after a pause', async () => {
    vi.useFakeTimers()
    const { rerender } = render(<AssetGroupsPage />)
    expect(state.filters).not.toHaveProperty('search')
    state.search = 'payments'
    rerender(<AssetGroupsPage />)
    // Still the old request while the user is typing.
    expect(state.filters).not.toHaveProperty('search')
    await act(async () => {
      vi.advanceTimersByTime(400)
    })
    expect(state.filters).toMatchObject({ search: 'payments' })
    vi.useRealTimers()
  })

  it('says when only the first groups are listed', () => {
    state.truncated = true
    state.total = 1500
    state.data = [
      {
        id: 'g1',
        name: 'one',
        environment: 'production',
        criticality: 'high',
        assetCount: 0,
        findingCount: 0,
        riskScore: 0,
      },
    ]
    render(<AssetGroupsPage />)
    expect(screen.getByText(/Showing the first 1000 of 1500 groups/)).toBeInTheDocument()
  })

  it('the title row says the list name, its one count and its actions', () => {
    state.data = [group('g1', 'payments')]
    state.total = 1
    render(<AssetGroupsPage />)
    expect(screen.getByRole('heading', { level: 2, name: 'All groups' })).toBeInTheDocument()
    expect(document.querySelectorAll('[data-slot="list-count"]')).toHaveLength(1)
    expect(screen.getByText('1 group')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Export' })).toBeInTheDocument()
  })

  it('a group name is a link to its page', () => {
    state.data = [group('g 1/x', 'payments')]
    state.total = 1
    render(<AssetGroupsPage />)
    expect(screen.getByRole('link', { name: 'payments' })).toHaveAttribute(
      'href',
      '/assets/groups/g%201%2Fx'
    )
  })

  it('an empty organization sees the first-run state, a narrowed list the no-match state', () => {
    const { unmount } = render(<AssetGroupsPage />)
    expect(screen.getByText('No asset groups yet')).toBeInTheDocument()
    expect(screen.queryByText('No asset groups found')).toBeNull()
    unmount()
    state.search = 'zzz'
    render(<AssetGroupsPage />)
    expect(screen.getByText('No asset groups found')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Clear filters' })).toBeInTheDocument()
  })

  it('has no checkbox column for a user without a bulk permission', () => {
    state.data = [group('g1', 'payments')]
    state.total = 1
    state.can = false
    render(<AssetGroupsPage />)
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
    state.can = true
  })

  it('has one filter entry and no docked panel', () => {
    render(<AssetGroupsPage />)
    expect(document.querySelectorAll('[data-slot="add-filter"]')).toHaveLength(1)
    expect(document.getElementById('asset-group-filters')).toBeNull()
  })
})
