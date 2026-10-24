import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const state = vi.hoisted(() => ({
  group: null as unknown,
  error: null as unknown,
  assets: [] as unknown[],
  refresh: vi.fn(),
  deleteGroup: vi.fn(),
  removeAssets: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/assets/groups/g1',
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
  useBreadcrumbTitle: () => {},
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' }, isLoading: false }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))
vi.mock('@/features/asset-types/api/use-asset-type-registry', () => ({
  useAssetTypeRegistry: () => ({ registry: undefined }),
}))
vi.mock('@/features/asset-groups', () => ({
  EditGroupDialog: () => null,
  AddAssetsDialog: () => null,
  useAssetGroup: () => ({
    data: state.group,
    isLoading: false,
    error: state.error,
    mutate: state.refresh,
  }),
  useGroupAssets: () => ({
    data: state.assets,
    total: state.assets.length,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useGroupFindings: () => ({ data: [], total: 0, isLoading: false }),
  useUpdateAssetGroup: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteAssetGroup: () => ({ trigger: state.deleteGroup, isMutating: false }),
  useRemoveAssetsFromGroup: () => ({ trigger: state.removeAssets, isMutating: false }),
  useAddAssetsToGroup: () => ({ trigger: vi.fn(), isMutating: false }),
}))

import AssetGroupDetailPage from '../[id]/page'

const group = {
  id: 'g1',
  name: 'Core',
  description: '',
  environment: 'production',
  criticality: 'high',
  assetCount: 340,
  findingCount: 0,
  riskScore: 10,
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-02T00:00:00Z',
  tags: [],
}

function renderPage() {
  // A settled thenable, so `use(params)` reads it without suspending.
  const value = { id: 'g1' }
  const params = Object.assign(Promise.resolve(value), { status: 'fulfilled', value })
  render(<AssetGroupDetailPage params={params} />)
}

beforeEach(() => {
  state.group = group
  state.assets = [
    { id: 'a1', name: 'web-01', type: 'host', status: 'active', riskScore: 1, findingCount: 0 },
    { id: 'a2', name: 'web-02', type: 'host', status: 'active', riskScore: 1, findingCount: 0 },
  ]
  state.deleteGroup.mockReset().mockResolvedValue(undefined)
  state.removeAssets.mockReset().mockResolvedValue(undefined)
})

describe('asset group detail confirmations', () => {
  it('deleting the group asks for its name first', async () => {
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'More actions' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /delete group/i }))
    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Delete group' })
    expect(confirm).toBeDisabled()
    expect(state.deleteGroup).not.toHaveBeenCalled()
    await userEvent.type(within(dialog).getByRole('textbox'), 'Core')
    await userEvent.click(confirm)
    await waitFor(() => expect(state.deleteGroup).toHaveBeenCalled())
  })

  it('removing selected assets names them and counts them in the button', async () => {
    renderPage()
    await userEvent.click(await screen.findByRole('tab', { name: /^assets/i }))
    await userEvent.click((await screen.findAllByRole('checkbox', { name: /select all/i }))[0])
    await userEvent.click(await screen.findByRole('button', { name: 'Remove 2 from group' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('web-01')).toBeInTheDocument()
    expect(state.removeAssets).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove 2 from group' }))
    await waitFor(() => expect(state.removeAssets).toHaveBeenCalledWith(['a1', 'a2']))
  })
})
