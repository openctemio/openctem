import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RolesTab, outsideMembersOf } from '../roles-tab'
import { MembersTab } from '../members-tab'
import { AddMemberDialog } from '../add-member-dialog'
import { ApiClientError } from '@/lib/api/error-handler'
import type { GroupMember } from '@/features/access-control'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

Element.prototype.scrollIntoView ??= () => {}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}

const bindGroupRole = vi.fn()

vi.mock('../../../api/use-group-roles', () => ({
  useGroupRoles: () => ({ roles: [], error: undefined, isLoading: false, mutate: vi.fn() }),
  bindGroupRole: (...a: unknown[]) => bindGroupRole(...a),
  unbindGroupRole: vi.fn(),
}))
vi.mock('../../../api/use-roles', () => ({
  useRoles: () => ({
    roles: [
      { id: 'r1', name: 'Analyst', is_system: false, has_full_data_access: false },
      { id: 'r2', name: 'Full data access', is_system: false, has_full_data_access: true },
    ],
  }),
  useRoleMembers: () => ({ members: [] }),
}))
vi.mock('../../add-member-to-role-dialog', () => ({
  AddMemberToRoleDialog: ({ role }: { role: { name: string } }) => (
    <div role="dialog">Grant {role.name}</div>
  ),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const outsider = { user_id: 'u9', name: 'Pat Contractor' }

describe('team with members outside the organization', () => {
  beforeEach(() => vi.clearAllMocks())

  it('turns off full-data roles up front and names who stands in the way', async () => {
    const onShow = vi.fn()
    const onCreate = vi.fn()
    render(
      <RolesTab
        groupId="g1"
        canBind
        canUnbind
        outsideMembers={[outsider, { user_id: 'u8', name: 'CI bot', service: true }]}
        onShowOutside={onShow}
        onCreateTeam={onCreate}
      />
    )
    const notice = screen.getByTestId('team-outside-notice')
    expect(notice).toHaveTextContent('Pat Contractor, CI bot (service account)')

    await userEvent.click(screen.getByRole('combobox', { name: 'Role to add' }))
    const off = await screen.findByRole('option', { name: /Full data access/ })
    expect(off).toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByRole('option', { name: 'Analyst' })).not.toHaveAttribute(
      'aria-disabled',
      'true'
    )
    await userEvent.keyboard('{Escape}')

    await userEvent.click(screen.getByRole('button', { name: 'Show them' }))
    expect(onShow).toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'New team without them' }))
    expect(onCreate).toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Give the role to a person' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Grant Full data access')
    expect(bindGroupRole).not.toHaveBeenCalled()
  })

  it('shows no notice for a team of insiders', () => {
    render(<RolesTab groupId="g1" canBind canUnbind outsideMembers={[]} />)
    expect(screen.queryByTestId('team-outside-notice')).not.toBeInTheDocument()
  })

  it('answers a refusal that raced the page with the named members, not a toast', async () => {
    bindGroupRole.mockRejectedValueOnce(
      new ApiClientError('refused', 'TEAM_EXTERNAL_FULL_DATA', 403, {
        outside_members: [outsider],
      })
    )
    const onChanged = vi.fn()
    render(<RolesTab groupId="g1" canBind canUnbind onChanged={onChanged} />)
    await userEvent.click(screen.getByRole('combobox', { name: 'Role to add' }))
    await userEvent.click(await screen.findByRole('option', { name: 'Full data access' }))
    await userEvent.click(screen.getByRole('button', { name: /^add role$/i }))
    await userEvent.click(await screen.findByRole('button', { name: /^add role$/i }))
    await waitFor(() =>
      expect(screen.getByTestId('team-outside-notice')).toHaveTextContent('Pat Contractor')
    )
    expect(onChanged).toHaveBeenCalled()
  })

  it('reads the outside members from a refusal only for its own code', () => {
    expect(
      outsideMembersOf(
        new ApiClientError('x', 'TEAM_EXTERNAL_FULL_DATA', 403, { outside_members: [outsider] })
      )
    ).toEqual([outsider])
    expect(outsideMembersOf(new ApiClientError('x', 'TEAM_EXTERNAL_FULL_DATA', 403))).toEqual([])
    expect(outsideMembersOf(new ApiClientError('x', 'FORBIDDEN', 403))).toBeNull()
    expect(outsideMembersOf(new Error('x'))).toBeNull()
  })

  it('marks outside members and filters to them', async () => {
    const members = [
      { user_id: 'u1', name: 'Ana Inside', email: 'ana@corp.test', role: 'member' },
      {
        user_id: 'u9',
        name: 'Pat Contractor',
        email: 'pat@vendor.test',
        role: 'member',
        outside: true,
      },
    ] as GroupMember[]
    const onToggle = vi.fn()
    const { rerender } = render(
      <MembersTab
        members={members}
        totalCount={2}
        isLoading={false}
        limit={20}
        offset={0}
        onPageChange={vi.fn()}
        onOutsideOnlyChange={onToggle}
      />
    )
    expect(screen.getAllByTestId('member-outside-badge')).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Outside organization only' }))
    expect(onToggle).toHaveBeenCalledWith(true)
    rerender(
      <MembersTab
        members={members}
        totalCount={2}
        isLoading={false}
        limit={20}
        offset={0}
        onPageChange={vi.fn()}
        outsideOnly
        onOutsideOnlyChange={onToggle}
      />
    )
    expect(screen.queryByText('Ana Inside')).not.toBeInTheDocument()
    expect(screen.getByText('Pat Contractor')).toBeInTheDocument()
  })

  it('does not let an outside person be picked for a full-data team', async () => {
    render(
      <AddMemberDialog
        open
        onOpenChange={vi.fn()}
        newMember={{ userId: '', role: 'member', endsOn: '', reason: '' }}
        setNewMember={vi.fn()}
        requireEnd={false}
        isAddingMember={false}
        onAddMember={vi.fn()}
        carriesFullData
        availableMembers={[
          { user_id: 'u1', name: 'Ana', email: 'ana@corp.test', kind: 'internal' },
          { user_id: 'u9', name: 'Pat', email: 'pat@vendor.test', kind: 'external' },
        ]}
      />
    )
    expect(screen.getByTestId('add-member-outside-note')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('combobox', { name: 'Member' }))
    expect(await screen.findByRole('option', { name: /Pat/ })).toHaveAttribute(
      'aria-disabled',
      'true'
    )
    expect(screen.getByRole('option', { name: /Ana/ })).not.toHaveAttribute('aria-disabled', 'true')
  })
})
