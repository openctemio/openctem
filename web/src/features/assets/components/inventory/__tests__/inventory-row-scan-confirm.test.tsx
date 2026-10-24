import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('../../asset-detail-sheet', () => ({
  AssetDetailSheet: ({ open, asset }: { open: boolean; asset: { name: string } }) =>
    open ? <div data-testid="drawer">{asset.name}</div> : null,
}))
const post = vi.hoisted(() => vi.fn())
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  post: (...a: unknown[]) => post(...a),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))
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
  name: 'acme/api',
  type: 'repository',
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

describe('InventoryTable row Scan', () => {
  it('asks before starting a scan and names the repository', async () => {
    post.mockReset().mockResolvedValue({})
    renderTable()
    fireEvent.pointerDown(screen.getByRole('button', { name: /Actions for acme\/api/ }), {
      button: 0,
      ctrlKey: false,
    })
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Scan' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Scan "acme/api" now?')
    expect(post).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Start scan' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
  })
})
