import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { OffboardMemberDialog } from '../offboard-member-dialog'
import type { MemberWithUser } from '../../types/member.types'

const offboardMember = vi.hoisted(() =>
  vi.fn().mockResolvedValue({ revoked_keys: 1, removed_groups: 0 })
)
vi.mock('../../api/use-members', () => ({
  offboardMember,
  useMembers: () => ({ members: [] }),
  useMemberAccessReport: () => ({
    report: {
      membership_id: 'm1',
      user_id: 'u1',
      status: 'active',
      roles: [],
      groups: [],
      api_keys: [],
      campaigns: [],
      direct_grants: 0,
      visible_assets: 0,
      owned_scans: [],
      owned_report_schedules: [],
      owned_workflows: [],
      assigned_findings: 0,
      owned_assets: 0,
      owned_tasks: 0,
      owned_campaigns: 0,
    },
    isLoading: false,
    mutate: vi.fn(),
  }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const member = { id: 'm1', user_id: 'u1', name: 'Lan Tran', email: 'lan@acme.example' }

describe('OffboardMemberDialog', () => {
  it('offboards only after the person is named', async () => {
    const user = userEvent.setup()
    render(
      <OffboardMemberDialog
        tenantSlug="acme"
        member={member as unknown as MemberWithUser}
        onOpenChange={vi.fn()}
        onOffboarded={vi.fn()}
      />
    )
    const button = screen.getByRole('button', { name: 'Offboard Lan Tran' })
    expect(button).toBeDisabled()
    await user.type(screen.getByLabelText(/Type Lan Tran to confirm/), 'Lan Tran')
    expect(button).toBeEnabled()
    await user.click(button)
    await waitFor(() => expect(offboardMember).toHaveBeenCalledWith('m1', expect.anything()))
  })
})
