import { describe, expect, it, vi } from 'vitest'
import { render } from '@testing-library/react'
import type { Asset } from '../../../types/asset.types'

const useGroups = vi.fn((..._args: unknown[]) => ({ groups: [], isLoading: false }))
vi.mock('../../../hooks/use-assets', () => ({ updateAsset: vi.fn() }))
vi.mock('../../../hooks/use-asset-owners', () => ({ addAssetOwner: vi.fn() }))
vi.mock('../inventory-business-context-actions', () => ({
  InventoryBusinessContextActions: () => null,
}))
vi.mock('swr', () => ({ default: () => ({ data: undefined, isLoading: false }) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: (...args: unknown[]) => useGroups(...args),
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

describe('bulk bar group list', () => {
  it('is not requested until the owner dialog opens', () => {
    const a = { id: 'a', name: 'a', type: 'domain', tags: [], metadata: {} } as unknown as Asset
    render(<InventoryBulkBar selected={[a]} canWrite onClear={vi.fn()} onDone={vi.fn()} />)
    expect(useGroups).toHaveBeenCalled()
    for (const call of useGroups.mock.calls) expect(call[1]).toBe(false)
  })
})
