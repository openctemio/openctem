import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FindingPeople } from '../finding-people'

let canManage = false
const blockProps = vi.fn()
vi.mock('@/lib/permissions', () => ({ useCanMutate: () => canManage }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (_k: string, fallback?: string) => fallback ?? _k }),
}))
vi.mock('../../../api/use-assignable-members', () => ({
  useAssignableMembers: (id: string, o: { enabled?: boolean }) => {
    blockProps({ id, enabled: o.enabled })
    return { members: [{ user_id: 'u1', name: 'Eligible', role: 'member' }], isLoading: false }
  },
}))
vi.mock('@/features/shared/components/watchers/watchers-control', () => ({
  WatchersControl: (p: Record<string, unknown>) => {
    blockProps({ block: p })
    return <div data-testid="watchers" />
  },
}))

beforeEach(() => {
  blockProps.mockReset()
})

describe('FindingPeople', () => {
  it('shows the People group with the assignee, and lets only people who may assign add', () => {
    canManage = false
    render(<FindingPeople findingId="f-1" assignee={<span>Minh N.</span>} />)
    expect(screen.getByRole('group', { name: 'People' })).toBeInTheDocument()
    expect(screen.getByText('Minh N.')).toBeInTheDocument()
    const call = blockProps.mock.calls.map((c) => c[0]).find((c) => c.block)
    expect(call.block).toMatchObject({
      kind: 'finding',
      itemId: 'f-1',
      canAdd: false,
      canRemoveOthers: false,
    })
  })

  it('offers the add picker, fed by the assignable endpoint, with the permission', () => {
    canManage = true
    render(<FindingPeople findingId="f-1" assignee={<span>x</span>} />)
    const call = blockProps.mock.calls.map((c) => c[0]).find((c) => c.block)
    expect(call.block).toMatchObject({ canAdd: true, canRemoveOthers: true })
    expect(call.block.picker.candidates).toEqual([{ id: 'u1', name: 'Eligible' }])
  })
})
