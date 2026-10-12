import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { GroupQuickView } from '../group-quick-view'
import type { AssetGroup } from '../../types'

const removeAssets = vi.hoisted(() => vi.fn(() => Promise.resolve()))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('../../hooks', () => ({
  useGroupAssets: () => ({
    data: [{ id: 'a1', name: 'api.acme.example', type: 'domain', status: 'active' }],
    isLoading: false,
    mutate: vi.fn(),
  }),
  useRemoveAssetsFromGroup: () => ({ trigger: removeAssets, isMutating: false }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const group = {
  id: 'g1',
  name: 'Internet edge',
  environment: 'production',
  criticality: 'high',
  assetCount: 1,
  findingCount: 0,
  riskScore: 0,
  createdAt: '2026-10-01T00:00:00Z',
  updatedAt: '2026-10-01T00:00:00Z',
} as unknown as AssetGroup

describe('Group quick view: remove an asset', () => {
  it('asks first and names the asset and the group', async () => {
    render(
      <GroupQuickView
        group={group}
        onClose={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onRefresh={vi.fn()}
      />
    )
    await userEvent.click(
      screen.getByRole('button', { name: 'Remove api.acme.example from the group' })
    )
    expect(removeAssets).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Remove api.acme.example from Internet edge?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(removeAssets).toHaveBeenCalledWith(['a1']))
  })
})
