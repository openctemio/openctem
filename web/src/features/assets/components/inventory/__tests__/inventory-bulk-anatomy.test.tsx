import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { Asset } from '../../../types/asset.types'

const denied = vi.hoisted(() => new Set<string>())
vi.mock('../../../hooks/use-assets', () => ({
  updateAsset: vi.fn(),
  deleteAsset: vi.fn(),
  archiveAsset: vi.fn(),
  bulkChangeAssetTags: vi.fn(),
}))
vi.mock('../../../hooks/use-asset-owners', () => ({ addAssetOwner: vi.fn() }))
vi.mock('../inventory-business-context-actions', () => ({
  InventoryBusinessContextActions: () => null,
  useBusinessContextAccess: () => ({ canUnit: true, canService: true }),
}))
vi.mock('swr', () => ({ default: () => ({ data: undefined, isLoading: false }) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: (p: string) => !denied.has(p) }),
  useHasPermission: (p: string) => !denied.has(p),
  Permission: {
    AssetsDelete: 'assets:delete',
    AssetsWrite: 'assets:write',
    ScopeWrite: 'scope:write',
    ScopeDelete: 'scope:delete',
    ScansExecute: 'scans:execute',
  },
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

import { InventoryBulkBar } from '../inventory-bulk-bar'

function asset(id: string, type = 'domain', tags: string[] = ['pci']): Asset {
  return { id, name: `${id}.example.com`, type, tags, metadata: {} } as unknown as Asset
}

function bar(selected: Asset[], canWrite = true) {
  render(
    <InventoryBulkBar selected={selected} canWrite={canWrite} onClear={vi.fn()} onDone={vi.fn()} />
  )
  return screen.queryByRole('toolbar', { name: 'Actions for selected rows' })
}

async function moreItems() {
  await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
  return (await screen.findAllByRole('menuitem')).map((i) => i.textContent?.trim())
}

beforeEach(() => denied.clear())

describe('asset bulk bar anatomy', () => {
  it('has two direct actions, More and Clear', () => {
    const toolbar = bar([asset('a'), asset('b')])!
    const names = within(toolbar)
      .getAllByRole('button')
      .map((b) => b.getAttribute('aria-label') ?? b.textContent?.trim())
    expect([...names].sort()).toEqual(
      ['Assign owner', 'Set criticality', 'More actions', 'Clear selection'].sort()
    )
  })

  it('keeps every other action under More, Delete last', async () => {
    bar([asset('a'), asset('r', 'repository')])
    expect(await moreItems()).toEqual([
      'Add to scope',
      'Mark out of scope',
      'Archive',
      'Add tag',
      'Remove tags',
      'Add to unit',
      'Add to service',
      'Scan',
      'Delete 2',
    ])
  })

  it('offers only the scope actions to someone with scope:write and no assets:write', async () => {
    denied.add('assets:write')
    const toolbar = bar([asset('a')], false)!
    expect(within(toolbar).queryByRole('button', { name: 'Assign owner' })).toBeNull()
    expect(await moreItems()).toEqual(['Add to scope', 'Mark out of scope'])
  })

  it('draws no bar for someone who may change nothing', () => {
    denied.add('assets:write')
    denied.add('scope:write')
    expect(bar([asset('a')], false)).toBeNull()
  })

  it('hides Delete without assets:delete', async () => {
    denied.add('assets:delete')
    bar([asset('a')])
    expect(await moreItems()).not.toContain('Delete 1')
  })
})
