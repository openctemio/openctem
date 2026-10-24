import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

vi.mock('../../asset-detail-sheet', () => ({
  AssetDetailSheet: ({
    open,
    asset,
    onDelete,
  }: {
    open: boolean
    asset: { name: string } | null
    onDelete: () => void
  }) =>
    open && asset ? (
      <div data-testid="drawer">
        {asset.name}
        <button type="button" onClick={onDelete}>
          drawer delete
        </button>
      </div>
    ) : null,
}))
vi.mock('@/features/scope', () => ({
  ScopeCheckBadge: () => null,
  useScopeCheck: () => ({ resultFor: () => undefined, data: undefined }),
}))
vi.mock('@/features/asset-types/api/use-asset-type-registry', () => ({
  useAssetTypeRegistry: () => ({ data: undefined, classAndLens: () => '' }),
}))
vi.mock('../../../hooks/use-asset-tags', () => ({ useAssetTags: () => ({ data: [] }) }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))

import { InventoryTable } from '../inventory-table'
import type { Asset } from '../../../types/asset.types'

const base = {
  id: '11111111-2222-3333-4444-555555555555',
  name: 'web-01',
  type: 'host',
  status: 'active',
  criticality: 'medium',
  exposure: 'private',
  scope: 'internal',
  findingCount: 0,
} as unknown as Asset

function table(assets: Asset[], onDeleteAsset = vi.fn()) {
  return (
    <InventoryTable
      assets={assets}
      total={assets.length}
      page={1}
      pageSize={20}
      onPageChange={() => {}}
      onSortChange={() => {}}
      onSelectionChange={() => {}}
      resetSelectionKey={0}
      hasFilters={false}
      onDeleteAsset={onDeleteAsset}
    />
  )
}

describe('InventoryTable drawer state', () => {
  it('shows the edited asset once the list refreshes', () => {
    const { rerender } = render(table([base]))
    fireEvent.click(screen.getAllByRole('link', { name: 'web-01' })[0])
    expect(screen.getByTestId('drawer')).toHaveTextContent('web-01')
    rerender(table([{ ...base, name: 'web-01-renamed' }]))
    expect(screen.getByTestId('drawer')).toHaveTextContent('web-01-renamed')
  })

  it('closes the drawer once the asset deleted from it leaves the list', () => {
    const onDelete = vi.fn()
    const { rerender } = render(table([base], onDelete))
    fireEvent.click(screen.getAllByRole('link', { name: 'web-01' })[0])
    fireEvent.click(screen.getByRole('button', { name: 'drawer delete' }))
    expect(onDelete).toHaveBeenCalled()
    // Still there until the delete goes through.
    expect(screen.getByTestId('drawer')).toBeInTheDocument()
    rerender(table([], onDelete))
    expect(screen.queryByTestId('drawer')).toBeNull()
  })
})
