import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

const m = vi.hoisted(() => ({
  create: vi.fn(),
  addMatching: vi.fn(),
  preview: vi.fn(),
  push: vi.fn(),
  can: vi.fn(() => true),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: m.push }) }))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: m.can }),
  Permission: { AssetGroupsWrite: 'assets:groups:write', AssetsWrite: 'assets:write' },
}))
vi.mock('../../api/use-asset-groups-api', () => ({
  useCreateAssetGroupApi: () => ({ trigger: m.create }),
  invalidateAssetGroupsCache: vi.fn(),
}))
vi.mock('../../api/use-group-rule-api', () => ({
  addMatchingToGroup: (...a: unknown[]) => m.addMatching(...a),
  previewGroupRule: (...a: unknown[]) => m.preview(...a),
  invalidateGroupMembership: vi.fn(),
}))
vi.mock('../asset-group-select', () => ({
  AssetGroupSelect: ({ onValueChange }: { onValueChange: (v: string) => void }) => (
    <button type="button" onClick={() => onValueChange('g1')}>
      pick group
    </button>
  ),
}))

import { FilterGroupActions } from '../filter-group-actions'

beforeEach(() => {
  Object.values(m).forEach((f) => 'mockReset' in f && (f as ReturnType<typeof vi.fn>).mockReset())
  m.can.mockReturnValue(true)
  m.preview.mockResolvedValue({
    count: 130,
    cap: 50000,
    over_cap: false,
    sample: [],
    would_join: 0,
    would_leave: 0,
  })
})

describe('FilterGroupActions', () => {
  it('shows nothing without permission, without a condition or without matches', () => {
    m.can.mockReturnValue(false)
    const { container, rerender } = render(
      <FilterGroupActions params={{ types: 'domain' }} total={5} />
    )
    expect(container).toBeEmptyDOMElement()
    m.can.mockReturnValue(true)
    rerender(<FilterGroupActions params={{ page: '1', per_page: '20' }} total={5} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<FilterGroupActions params={{ types: 'domain' }} total={0} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('saves the filter on screen as a rule group and opens it', async () => {
    m.create.mockResolvedValue({ id: 'new-group' })
    render(<FilterGroupActions params={{ types: 'domain', tags: 'prod', page: '3' }} total={130} />)
    fireEvent.click(screen.getByRole('button', { name: /save filter as group/i }))
    const create = screen.getByRole('button', { name: /create group/i })
    expect(create).toBeDisabled()
    fireEvent.change(screen.getByLabelText(/group name/i), { target: { value: 'Prod domains' } })
    fireEvent.click(create)
    await waitFor(() => expect(m.create).toHaveBeenCalled())
    expect(m.create.mock.calls[0][0]).toMatchObject({
      name: 'Prod domains',
      rule: { v: 1, filter: { types: ['domain'], tags: ['prod'] } },
    })
    await waitFor(() => expect(m.push).toHaveBeenCalledWith('/assets/groups/new-group'))
  })

  it('names the filters a rule cannot hold', () => {
    render(
      <FilterGroupActions params={{ types: 'domain', last_seen_after: '2026-10-01' }} total={9} />
    )
    fireEvent.click(screen.getByRole('button', { name: /save filter as group/i }))
    expect(screen.getByTestId('filter-unsupported')).toHaveTextContent('last_seen_after')
  })

  it('adds everything the filter matches, not only the page, and shows the impact', async () => {
    m.addMatching.mockResolvedValue({
      matched: 130,
      added: 120,
      impact: {
        widens: true,
        would_join: 120,
        teams: [{ id: 't', name: 'Payments' }],
        scans: [],
        privileged_team: false,
      },
    })
    render(<FilterGroupActions params={{ search: 'pti' }} total={130} />)
    fireEvent.click(screen.getByRole('button', { name: /add all 130 matching to group/i }))
    const add = screen.getByRole('button', { name: /^add to group$/i })
    expect(add).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: /pick group/i }))
    fireEvent.click(add)
    await waitFor(() =>
      expect(m.addMatching).toHaveBeenCalledWith('g1', { v: 1, filter: { search: 'pti' } })
    )
    const result = await screen.findByTestId('add-matching-result')
    expect(result).toHaveTextContent('120 assets added')
    expect(screen.getByTestId('group-impact-notice')).toHaveTextContent('Payments')
  })
})
