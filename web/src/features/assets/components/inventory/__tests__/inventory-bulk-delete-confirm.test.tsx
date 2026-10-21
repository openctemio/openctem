import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { Asset } from '../../../types/asset.types'

const deleteAsset = vi.fn()
vi.mock('../../../hooks/use-assets', () => ({
  updateAsset: vi.fn(),
  deleteAsset: (...args: unknown[]) => deleteAsset(...args),
  archiveAsset: vi.fn(),
}))
vi.mock('../../../hooks/use-asset-owners', () => ({ addAssetOwner: vi.fn() }))
vi.mock('../inventory-business-context-actions', () => ({
  InventoryBusinessContextActions: () => null,
}))
vi.mock('swr', () => ({ default: () => ({ data: undefined, isLoading: false }) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: () => true }),
  useHasPermission: () => true,
  Permission: {
    AssetsDelete: 'assets:delete',
    AssetsWrite: 'assets:write',
    ScopeWrite: 'scope:write',
  },
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

import { InventoryBulkBar } from '../inventory-bulk-bar'

function asset(id: string, findingCount = 0): Asset {
  return {
    id,
    name: `${id}.example.com`,
    type: 'domain',
    criticality: 'low',
    tags: [],
    metadata: {},
    findingCount,
  } as unknown as Asset
}

beforeEach(() => deleteAsset.mockReset().mockResolvedValue(undefined))

async function openDelete(selected: Asset[]) {
  const onDone = vi.fn()
  render(<InventoryBulkBar selected={selected} canWrite onClear={vi.fn()} onDone={onDone} />)
  await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
  return { dialog: await screen.findByRole('alertdialog'), onDone }
}

describe('bulk asset delete confirmation', () => {
  it('asks for the count, names the action and shows which assets it touches', async () => {
    const { dialog, onDone } = await openDelete([asset('a'), asset('b', 2), asset('c')])
    expect(within(dialog).getByText('a.example.com')).toBeInTheDocument()
    expect(within(dialog).getByText('c.example.com')).toBeInTheDocument()
    expect(within(dialog).getByText(/1 of them has findings/)).toBeInTheDocument()
    const confirm = within(dialog).getByRole('button', { name: 'Delete 3 assets' })
    expect(confirm).toBeDisabled()
    await userEvent.type(within(dialog).getByRole('textbox'), '3')
    await userEvent.click(confirm)
    await waitFor(() => expect(onDone).toHaveBeenCalled())
    expect(deleteAsset).toHaveBeenCalledTimes(3)
  })

  it('asks for the name when one asset is selected', async () => {
    const { dialog } = await openDelete([asset('solo')])
    const confirm = within(dialog).getByRole('button', { name: 'Delete 1 asset' })
    await userEvent.type(within(dialog).getByRole('textbox'), '1')
    expect(confirm).toBeDisabled()
    await userEvent.clear(within(dialog).getByRole('textbox'))
    await userEvent.type(within(dialog).getByRole('textbox'), 'solo.example.com')
    expect(confirm).toBeEnabled()
  })

  it('does not delete anything without the typed confirmation', async () => {
    const { dialog } = await openDelete([asset('a'), asset('b')])
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete 2 assets' }))
    expect(deleteAsset).not.toHaveBeenCalled()
  })
})
