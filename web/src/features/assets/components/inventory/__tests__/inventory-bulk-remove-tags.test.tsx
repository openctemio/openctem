import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { Asset } from '../../../types/asset.types'

const updateAsset = vi.fn()
vi.mock('../../../hooks/use-assets', () => ({
  updateAsset: (...args: unknown[]) => updateAsset(...args),
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

function asset(id: string, tags: string[]): Asset {
  return {
    id,
    name: id,
    type: 'domain',
    criticality: 'low',
    tags,
    metadata: {},
  } as unknown as Asset
}

beforeEach(() => updateAsset.mockReset().mockResolvedValue({}))

describe('bulk remove tags', () => {
  it('is offered only when the selection carries tags', () => {
    render(
      <InventoryBulkBar selected={[asset('a', [])]} canWrite onClear={vi.fn()} onDone={vi.fn()} />
    )
    expect(screen.queryByRole('button', { name: 'Remove tags' })).toBeNull()
  })

  it('removes the ticked tags from the assets that carry them, keeping the others', async () => {
    const onDone = vi.fn()
    render(
      <InventoryBulkBar
        selected={[asset('a', ['pci', 'prod']), asset('b', ['prod']), asset('c', ['other'])]}
        canWrite
        onClear={vi.fn()}
        onDone={onDone}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: 'Remove tags' }))
    const dialog = await screen.findByRole('dialog')
    // Most common first, with how many selected assets carry each.
    expect(within(dialog).getByText('2 of 3')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByLabelText(/^pci/))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove 1 tags from 3 selected' }))
    await waitFor(() => expect(onDone).toHaveBeenCalled())
    // Only asset a carries pci: one write, its other tag kept.
    expect(updateAsset).toHaveBeenCalledTimes(1)
    expect(updateAsset).toHaveBeenCalledWith('a', expect.objectContaining({ tags: ['prod'] }))
  })
})
