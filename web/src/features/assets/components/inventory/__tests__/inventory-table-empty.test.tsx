import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('../../asset-detail-sheet', () => ({
  AssetDetailSheet: ({ open, asset }: { open: boolean; asset: { name: string } }) =>
    open ? <div data-testid="drawer">{asset.name}</div> : null,
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

function renderEmpty(hasFilters: boolean) {
  render(
    <InventoryTable
      assets={[]}
      total={0}
      page={1}
      pageSize={20}
      onPageChange={() => {}}
      onSortChange={() => {}}
      onSelectionChange={() => {}}
      resetSelectionKey={0}
      hasFilters={hasFilters}
    />
  )
}

describe('InventoryTable empty list', () => {
  it('says no assets exist yet when no filter is applied', () => {
    renderEmpty(false)
    expect(screen.getByText('No assets in this organization yet')).toBeInTheDocument()
    expect(screen.queryByText('No assets match these filters')).toBeNull()
  })

  it('says nothing matches when a filter is applied', () => {
    renderEmpty(true)
    expect(screen.getByText('No assets match these filters')).toBeInTheDocument()
    expect(screen.getByText('Try removing a filter or clearing them all.')).toBeInTheDocument()
  })
})
