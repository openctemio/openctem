import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

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
import type { Asset } from '../../../types/asset.types'

const asset = {
  id: '11111111-2222-3333-4444-555555555555',
  name: 'web-01',
  type: 'host',
  status: 'active',
  criticality: 'medium',
  exposure: 'private',
  scope: 'internal',
  findingCount: 0,
} as unknown as Asset

function renderTable() {
  render(
    <InventoryTable
      assets={[asset]}
      total={1}
      page={1}
      pageSize={20}
      onPageChange={() => {}}
      onSortChange={() => {}}
      onSelectionChange={() => {}}
      resetSelectionKey={0}
      hasFilters={false}
    />
  )
}

describe('InventoryTable name link', () => {
  it('links the name to the asset page', () => {
    renderTable()
    const link = screen.getAllByRole('link', { name: 'web-01' })[0]
    expect(link).toHaveAttribute('href', `/assets/${asset.id}`)
  })

  it('a plain click opens the drawer', () => {
    renderTable()
    fireEvent.click(screen.getAllByRole('link', { name: 'web-01' })[0])
    expect(screen.getByTestId('drawer')).toBeInTheDocument()
  })

  it('a ctrl or cmd click leaves navigation to the browser', () => {
    renderTable()
    const link = screen.getAllByRole('link', { name: 'web-01' })[0]
    fireEvent.click(link, { ctrlKey: true })
    fireEvent.click(link, { metaKey: true })
    expect(screen.queryByTestId('drawer')).toBeNull()
  })

  it('the row menu offers the details page as a real link', async () => {
    renderTable()
    fireEvent.pointerDown(screen.getByRole('button', { name: /Actions for web-01/ }), {
      button: 0,
      ctrlKey: false,
    })
    const item = await screen.findByRole('menuitem', { name: /Open details page/ })
    expect(item).toHaveAttribute('href', `/assets/${asset.id}`)
  })
})
