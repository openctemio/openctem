import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RolesTab } from '../roles-tab'
import { MembershipEndDialog, membershipEndISO } from '../membership-end'
import { MembersTab } from '../members-tab'
import { AddMemberDialog } from '../add-member-dialog'
import type { GroupMember } from '@/features/access-control'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const bindGroupRole = vi.fn()
const unbindGroupRole = vi.fn()
const setGroupMemberExpiry = vi.fn()
let bound: unknown[] = []

vi.mock('../../../api/use-group-roles', () => ({
  useGroupRoles: () => ({ roles: bound, error: undefined, isLoading: false, mutate: vi.fn() }),
  bindGroupRole: (...a: unknown[]) => bindGroupRole(...a),
  unbindGroupRole: (...a: unknown[]) => unbindGroupRole(...a),
  setGroupMemberExpiry: (...a: unknown[]) => setGroupMemberExpiry(...a),
}))
vi.mock('../../../api/use-roles', () => ({
  useRoles: () => ({
    roles: [
      { id: 'sys', name: 'Viewer', is_system: true, has_full_data_access: false },
      { id: 'r1', name: 'Analyst', is_system: false, has_full_data_access: false },
      { id: 'r2', name: 'Auditor', is_system: false, has_full_data_access: true },
    ],
  }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('RolesTab', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    bound = [
      { role_id: 'r2', name: 'Auditor', privileged: true, created_at: '2026-10-01T00:00:00Z' },
    ]
  })

  it('shows bound roles with their privileged and full-data marks', () => {
    render(<RolesTab groupId="g1" canBind canUnbind />)
    expect(screen.getByText('Auditor')).toBeInTheDocument()
    expect(screen.getByText('Privileged')).toBeInTheDocument()
    expect(screen.getByText('Full data access')).toBeInTheDocument()
  })

  it('removes a role only after confirmation', async () => {
    unbindGroupRole.mockResolvedValueOnce(undefined)
    render(<RolesTab groupId="g1" canBind canUnbind />)
    await userEvent.click(screen.getByRole('button', { name: 'Remove role Auditor' }))
    expect(unbindGroupRole).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: /^remove$/i }))
    expect(unbindGroupRole).toHaveBeenCalledWith('g1', 'r2')
  })

  it('offers no controls to someone who may only read', () => {
    render(<RolesTab groupId="g1" canBind={false} canUnbind={false} />)
    expect(screen.queryByRole('button', { name: /add role/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove role Auditor' })).not.toBeInTheDocument()
  })
})

describe('membership end date', () => {
  beforeEach(() => vi.clearAllMocks())

  it('sends the end of the chosen day, and nothing for no end', () => {
    expect(membershipEndISO('2026-12-31')).toBe('2026-12-31T23:59:59Z')
    expect(membershipEndISO('')).toBeUndefined()
  })

  it('clears the end date of an internal team member', async () => {
    setGroupMemberExpiry.mockResolvedValueOnce(undefined)
    render(
      <MembershipEndDialog
        groupId="g1"
        member={{ userId: 'u1', name: 'Bob', expiresAt: '2026-12-31T23:59:59Z' }}
        required={false}
        onOpenChange={vi.fn()}
      />
    )
    await userEvent.clear(screen.getByLabelText(/membership ends/i))
    await userEvent.click(screen.getByRole('button', { name: /^save$/i }))
    expect(setGroupMemberExpiry).toHaveBeenCalledWith('g1', 'u1', {
      expires_at: null,
      reason: undefined,
    })
  })

  it('refuses to clear the end date on an external team', async () => {
    render(
      <MembershipEndDialog
        groupId="g1"
        member={{ userId: 'u1', name: 'Bob', expiresAt: '2026-12-31T23:59:59Z' }}
        required
        onOpenChange={vi.fn()}
      />
    )
    const input = screen.getByLabelText(/membership ends/i)
    expect(input).toBeRequired()
    await userEvent.clear(input)
    await userEvent.click(screen.getByRole('button', { name: /^save$/i }))
    expect(setGroupMemberExpiry).not.toHaveBeenCalled()
  })

  it('the add-member dialog cannot add to an external team without an end date', () => {
    render(
      <AddMemberDialog
        open
        onOpenChange={vi.fn()}
        newMember={{ userId: 'u1', role: 'member', endsOn: '', reason: '' }}
        setNewMember={vi.fn()}
        isAddingMember={false}
        onAddMember={vi.fn()}
        availableMembers={[{ user_id: 'u1', name: 'Bob', email: 'bob@example.com' }]}
        requireEnd
      />
    )
    expect(screen.getByRole('button', { name: /add member/i })).toBeDisabled()
  })

  it('the members list shows the end date and offers to change it', async () => {
    const onChangeEnd = vi.fn()
    const member = {
      id: 'm1',
      group_id: 'g1',
      user_id: 'u1',
      role: 'member',
      joined_at: '2026-10-01T00:00:00Z',
      name: 'Bob',
      email: 'bob@example.com',
      expires_at: '2026-12-31T23:59:59Z',
    } as GroupMember
    render(
      <MembersTab
        members={[member]}
        totalCount={1}
        isLoading={false}
        limit={20}
        offset={0}
        onPageChange={vi.fn()}
        onChangeEnd={onChangeEnd}
      />
    )
    expect(screen.getByText(/^Ends /)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /open menu|actions/i }))
    await userEvent.click(await screen.findByText('Change end date'))
    expect(onChangeEnd).toHaveBeenCalledWith('u1', 'Bob', '2026-12-31T23:59:59Z')
  })
})
