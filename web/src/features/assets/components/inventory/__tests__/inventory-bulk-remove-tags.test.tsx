import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { Asset } from '../../../types/asset.types'

const updateAsset = vi.fn()
const bulkChangeAssetTags = vi.fn()
vi.mock('../../../hooks/use-assets', () => ({
  updateAsset: (...args: unknown[]) => updateAsset(...args),
  bulkChangeAssetTags: (...args: unknown[]) => bulkChangeAssetTags(...args),
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

beforeEach(() => {
  updateAsset.mockReset().mockResolvedValue({})
  bulkChangeAssetTags.mockReset().mockResolvedValue({ updated: 1, unchanged: 0, failed: 0 })
})

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
    // Only asset a carries pci: one change naming only that tag, applied by
    // the API to the stored tags (never a list built from the row's copy).
    expect(bulkChangeAssetTags).toHaveBeenCalledTimes(1)
    expect(bulkChangeAssetTags).toHaveBeenCalledWith(['a'], { remove: ['pci'] })
    expect(updateAsset).not.toHaveBeenCalled()
  })
})

describe('bulk add tag', () => {
  it('sends one change for the whole selection, never the rows\' tag lists', async () => {
    const onDone = vi.fn()
    render(
      <InventoryBulkBar
        selected={[asset('a', ['pci']), asset('b', [])]}
        canWrite
        onClear={vi.fn()}
        onDone={onDone}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: 'Add tag' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Tag'), { target: { value: ' dmz ' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add tag to 2 selected' }))
    await waitFor(() => expect(onDone).toHaveBeenCalled())
    expect(bulkChangeAssetTags).toHaveBeenCalledWith(['a', 'b'], { add: ['dmz'] })
    expect(updateAsset).not.toHaveBeenCalled()
  })
})

describe('bulk criticality', () => {
  it('sends only the criticality, not the rows\' copies of other fields', async () => {
    const onDone = vi.fn()
    render(
      <InventoryBulkBar
        selected={[asset('a', ['pci'])]}
        canWrite
        onClear={vi.fn()}
        onDone={onDone}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: 'Set criticality' }))
    const dialog = await screen.findByRole('dialog')
    const buttons = within(dialog).getAllByRole('button')
    fireEvent.click(buttons[buttons.length - 1])
    await waitFor(() => expect(updateAsset).toHaveBeenCalled())
    expect(updateAsset).toHaveBeenCalledWith('a', { criticality: 'high' })
  })
})
