import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { Asset } from '../../../types/asset.types'

const deleteAsset = vi.fn()
const post = vi.hoisted(() => vi.fn())
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  post: (...a: unknown[]) => post(...a),
}))
vi.mock('../../../hooks/use-assets', () => ({
  updateAsset: vi.fn(),
  deleteAsset: (...args: unknown[]) => deleteAsset(...args),
  archiveAsset: vi.fn(),
}))
vi.mock('../../../hooks/use-asset-owners', () => ({ addAssetOwner: vi.fn() }))
vi.mock('../inventory-business-context-actions', () => ({
  InventoryBusinessContextActions: () => null,
  useBusinessContextAccess: () => ({ canUnit: false, canService: false }),
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
    ScansExecute: 'scans:execute',
  },
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

import { InventoryBulkBar } from '../inventory-bulk-bar'

function repo(id: string): Asset {
  return {
    id,
    name: `acme/${id}`,
    type: 'repository',
    criticality: 'low',
    tags: [],
    metadata: {},
    findingCount: 0,
  } as unknown as Asset
}

describe('bulk repository scan confirmation', () => {
  it('names the count and the repositories before sending any scan', async () => {
    post.mockReset().mockResolvedValue({})
    render(
      <InventoryBulkBar
        selected={[repo('a'), repo('b')]}
        canWrite
        onClear={vi.fn()}
        onDone={vi.fn()}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Scan' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Scan 2 repositories now?')
    expect(within(dialog).getByText('acme/a')).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Start 2 scans' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(2))
  })

  it('keeps Delete last in More, as the destructive item', async () => {
    render(<InventoryBulkBar selected={[repo('a')]} canWrite onClear={vi.fn()} onDone={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    const items = await screen.findAllByRole('menuitem')
    expect(items.at(-1)).toHaveAccessibleName('Delete 1')
    expect(items.at(-1)?.getAttribute('data-variant')).toBe('destructive')
  })
})
