import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const state = vi.hoisted(() => ({
  isError: false,
  data: [] as unknown[],
  truncated: false,
  total: 0,
  refresh: vi.fn(),
  filters: undefined as unknown,
  bulkDelete: vi.fn(),
  bulkUpdate: vi.fn(),
  deleteTrigger: vi.fn(),
  search: '',
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
  usePermissions: () => ({ can: () => true }),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
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
  useDeleteAssetGroup: () => ({ trigger: state.deleteTrigger }),
  useAddAssetsToGroup: () => ({ trigger: vi.fn(), isMutating: false }),
  useBulkAssetGroupOperations: () => ({
    bulkDelete: state.bulkDelete,
    bulkUpdate: state.bulkUpdate,
  }),
}))

import AssetGroupsPage from '../page'

const group = (id: string, name: string) => ({
  id,
  name,
  environment: 'production',
  criticality: 'high',
  assetCount: 0,
  findingCount: 0,
  riskScore: 0,
})

beforeEach(() => {
  state.data = [group('g1', 'payments'), group('g2', 'billing')]
  state.total = 2
  state.search = ''
  state.bulkDelete.mockReset().mockResolvedValue(undefined)
  state.bulkUpdate.mockReset().mockResolvedValue(undefined)
  state.deleteTrigger.mockReset().mockResolvedValue(undefined)
})

async function selectAll() {
  render(<AssetGroupsPage />)
  const boxes = screen.getAllByRole('checkbox', { name: /select all/i })
  await userEvent.click(boxes[0])
}

describe('asset group bulk confirmations', () => {
  it('bulk delete asks for the count, names the groups and does not delete before it', async () => {
    await selectAll()
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('payments')).toBeInTheDocument()
    expect(within(dialog).getByText('billing')).toBeInTheDocument()
    const confirm = within(dialog).getByRole('button', { name: 'Delete 2 groups' })
    expect(confirm).toBeDisabled()
    expect(state.bulkDelete).not.toHaveBeenCalled()
    await userEvent.type(within(dialog).getByRole('textbox'), '2')
    await userEvent.click(confirm)
    await waitFor(() => expect(state.bulkDelete).toHaveBeenCalledWith(['g1', 'g2']))
  })

  it('bulk delete is styled as destructive', async () => {
    await selectAll()
    const bar = await screen.findByRole('button', { name: 'Delete' })
    expect(bar.className).toContain('destructive')
  })

  it('a bulk criticality change waits for the confirmation', async () => {
    await selectAll()
    const bar = await screen.findByRole('toolbar')
    await userEvent.click(within(bar).getByRole('button', { name: /^criticality$/i }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /critical/i }))
    expect(state.bulkUpdate).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('payments')).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Update 2 selected' }))
    await waitFor(() =>
      expect(state.bulkUpdate).toHaveBeenCalledWith(['g1', 'g2'], { criticality: 'critical' })
    )
  })
})
