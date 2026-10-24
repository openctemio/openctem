import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { post } from '@/lib/api/client'

const state = {
  owner: false,
  stats: undefined as { role_counts: Record<string, number> } | undefined,
}

vi.mock('@/lib/api/client', () => ({ post: vi.fn() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/cookies', () => ({ removeCookie: vi.fn() }))
vi.mock('@/lib/permissions', () => ({ usePermissions: () => ({ isOwner: () => state.owner }) }))
vi.mock('../../api/use-members', () => ({ useMemberStats: () => ({ stats: state.stats }) }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({
    currentTenant: { id: 't1', slug: 'acme', name: 'Acme' },
    tenants: [{ id: 't1', slug: 'acme', name: 'Acme' }],
    switchTeam: vi.fn(),
    loadTenants: vi.fn(),
  }),
}))

import { LeaveOrganization } from '../leave-organization'

describe('LeaveOrganization', () => {
  beforeEach(() => {
    state.owner = false
    state.stats = undefined
  })

  it('lets a member leave: the button is enabled', () => {
    render(<LeaveOrganization />)
    expect(screen.getByRole('button', { name: /leave organization/i })).toBeEnabled()
    expect(screen.getByText(/organization membership/i)).toBeInTheDocument()
  })

  it('lets an owner leave when another owner exists', () => {
    state.owner = true
    state.stats = { role_counts: { owner: 2 } }
    render(<LeaveOrganization />)
    expect(screen.getByRole('button', { name: /leave organization/i })).toBeEnabled()
  })

  it('shows the sole owner a disabled button with the reason', () => {
    state.owner = true
    state.stats = { role_counts: { owner: 1 } }
    render(<LeaveOrganization />)
    expect(screen.getByRole('button', { name: /leave organization/i })).toBeDisabled()
    expect(screen.getByText(/transfer ownership to another member first/i)).toBeInTheDocument()
  })

  it('leaves only after typing the organization name', async () => {
    vi.mocked(post).mockResolvedValue({})
    const user = userEvent.setup()
    render(<LeaveOrganization />)
    await user.click(screen.getByRole('button', { name: /leave organization/i }))
    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: /leave organization/i })
    expect(confirm).toBeDisabled()
    await user.click(confirm)
    expect(post).not.toHaveBeenCalled()
    await user.type(within(dialog).getByRole('textbox'), 'Acme')
    expect(confirm).toBeEnabled()
    await user.click(confirm)
    expect(post).toHaveBeenCalled()
  })
})
