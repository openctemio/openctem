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
const toast = vi.hoisted(() => ({
  success: vi.fn(),
  warning: vi.fn(),
  error: vi.fn(),
  info: vi.fn(),
}))
vi.mock('sonner', () => ({ toast }))

import { InventoryBulkBar } from '../inventory-bulk-bar'

function asset(id: string): Asset {
  return {
    id,
    name: id,
    type: 'domain',
    criticality: 'critical',
    tags: [],
    metadata: {},
  } as unknown as Asset
}

async function applyHigh(onDone = vi.fn()) {
  render(
    <InventoryBulkBar
      selected={[asset('a'), asset('b'), asset('c')]}
      canWrite
      onClear={vi.fn()}
      onDone={onDone}
    />
  )
  fireEvent.click(screen.getByRole('button', { name: 'Set criticality' }))
  const dialog = await screen.findByRole('dialog')
  fireEvent.click(within(dialog).getByRole('button', { name: 'Apply to 3 selected' }))
  await waitFor(() => expect(updateAsset).toHaveBeenCalledTimes(3))
}

beforeEach(() => {
  updateAsset.mockReset()
  Object.values(toast).forEach((f) => f.mockReset())
})

describe('bulk set criticality', () => {
  it('says which lowered values wait for approval instead of reporting them as set', async () => {
    updateAsset.mockImplementation((id: string) =>
      Promise.resolve(id === 'b' ? { id, pendingRiskRequest: { id: 'req-1' } } : { id })
    )
    await applyHigh()
    await waitFor(() => expect(toast.warning).toHaveBeenCalled())
    expect(toast.warning).toHaveBeenCalledWith(
      'Set criticality to High for 2 of 3; 1 waiting for approval'
    )
    expect(toast.success).not.toHaveBeenCalled()
  })

  it('counts approvals and failures apart', async () => {
    updateAsset.mockImplementation((id: string) =>
      id === 'c'
        ? Promise.reject(new Error('boom'))
        : Promise.resolve(id === 'b' ? { id, pendingRiskRequest: { id: 'req-1' } } : { id })
    )
    await applyHigh()
    await waitFor(() => expect(toast.warning).toHaveBeenCalled())
    expect(toast.warning).toHaveBeenCalledWith(
      'Set criticality to High for 1 of 3; 1 waiting for approval; 1 failed'
    )
  })

  it('reports success when every value was set', async () => {
    updateAsset.mockImplementation((id: string) => Promise.resolve({ id }))
    await applyHigh()
    await waitFor(() => expect(toast.success).toHaveBeenCalled())
    expect(toast.success).toHaveBeenCalledWith('Set criticality to High for 3 assets')
    expect(toast.warning).not.toHaveBeenCalled()
  })
})
