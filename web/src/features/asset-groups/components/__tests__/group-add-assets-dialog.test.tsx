import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'

const state = vi.hoisted(() => ({
  calls: [] as unknown[],
  assets: [] as unknown[],
  total: 0,
  members: [] as unknown[],
}))

vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAssets: (filters: unknown) => {
    state.calls.push(filters)
    return { assets: state.assets, total: state.total, isLoading: false }
  },
}))
vi.mock('../../hooks/use-asset-groups', () => ({
  useAddAssetsToGroup: () => ({ trigger: vi.fn(), isMutating: false }),
  useGroupAssets: () => ({ data: state.members }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' }, isLoading: false }),
}))

import { GroupAddAssetsDialog } from '../group-add-assets-dialog'
import type { AssetGroup } from '../../types'

const group = { id: 'g1', name: 'Core' } as AssetGroup
const asset = (id: string, name: string) => ({ id, name, type: 'host', riskScore: 10 })

beforeEach(() => {
  state.calls = []
  state.assets = [asset('a1', 'alpha'), asset('a2', 'beta')]
  state.total = 2
  state.members = []
})

describe('GroupAddAssetsDialog', () => {
  it('searches the server, one page at a time, after a pause', async () => {
    vi.useFakeTimers()
    render(<GroupAddAssetsDialog group={group} onClose={() => {}} onSuccess={() => {}} />)
    fireEvent.change(screen.getByRole('textbox', { name: /search assets/i }), {
      target: { value: 'edge-1' },
    })
    await act(async () => {
      vi.advanceTimersByTime(400)
    })
    vi.useRealTimers()
    expect(state.calls[state.calls.length - 1]).toMatchObject({ search: 'edge-1', pageSize: 20 })
  })

  it('leaves out the assets already in the group', () => {
    state.members = [{ id: 'a1' }]
    render(<GroupAddAssetsDialog group={group} onClose={() => {}} onSuccess={() => {}} />)
    expect(screen.queryByText('alpha')).toBeNull()
    expect(screen.getByText('beta')).toBeInTheDocument()
  })

  it('says when the search has more results than the page shows', () => {
    state.total = 340
    render(<GroupAddAssetsDialog group={group} onClose={() => {}} onSuccess={() => {}} />)
    expect(screen.getByText(/Showing 2 of 340/)).toBeInTheDocument()
  })
})
