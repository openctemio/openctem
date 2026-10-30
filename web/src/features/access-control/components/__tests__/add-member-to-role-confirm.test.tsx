import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AddMemberToRoleDialog } from '../add-member-to-role-dialog'
import type { Role } from '@/features/access-control'

const bulkAssignMembers = vi.hoisted(() =>
  vi.fn().mockResolvedValue({ success_count: 2, failed_count: 0 })
)
vi.mock('@/features/access-control', async (orig) => ({
  ...(await orig<typeof import('@/features/access-control')>()),
  useBulkAssignRoleMembers: () => ({ bulkAssignMembers, isAssigning: false }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { slug: 'acme' }, isLoading: false }),
}))
vi.mock('@/features/organization', () => ({
  useMembers: () => ({
    members: [
      { user_id: 'u1', name: 'Lan Tran', email: 'lan@acme.example' },
      { user_id: 'u2', name: 'Minh Le', email: 'minh@acme.example' },
    ],
    isLoading: false,
    isError: false,
  }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe('AddMemberToRoleDialog', () => {
  it('names the people and the role before adding, then adds after confirming', async () => {
    const user = userEvent.setup()
    const role = { id: 'r1', name: 'Analyst', permission_count: 7 } as unknown as Role
    render(<AddMemberToRoleDialog role={role} open onOpenChange={vi.fn()} existingMembers={[]} />)
    await user.click(screen.getByText('Lan Tran'))
    await user.click(screen.getByText('Minh Le'))
    await user.click(screen.getByRole('button', { name: 'Add 2 members' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Add 2 members to Analyst?')
    expect(dialog).toHaveTextContent('7 permissions')
    expect(dialog).toHaveTextContent('Lan Tran')
    expect(bulkAssignMembers).not.toHaveBeenCalled()
    const buttons = screen.getAllByRole('button', { name: 'Add 2 members' })
    await user.click(buttons[buttons.length - 1])
    await waitFor(() => expect(bulkAssignMembers).toHaveBeenCalledWith({ user_ids: ['u1', 'u2'] }))
  })
})
