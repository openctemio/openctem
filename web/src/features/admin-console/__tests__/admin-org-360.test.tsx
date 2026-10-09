import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { recoverOrganizationOwner, useOrganizationUsers } from '../api/use-admin-organizations'
import { AdminApiError } from '../api/admin-client'
import { OrganizationUsersSection } from '../components/organization-users-section'
import { AdminConfirmDialog } from '../components/admin-confirm-dialog'

vi.mock('../api/use-admin-organizations', () => ({
  createOrganizationUser: vi.fn(),
  recoverOrganizationOwner: vi.fn(),
  useOrganizationUsers: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const suspendedOwner = {
  user_id: 'u1',
  email: 'gone@acme.test',
  name: 'Gone',
  role: 'owner',
  status: 'suspended',
  pending_setup: false,
  joined_at: '2026-01-01T00:00:00Z',
}

function users(rows: (typeof suspendedOwner)[]) {
  return {
    data: { data: rows, total: rows.length },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  } as unknown as ReturnType<typeof useOrganizationUsers>
}

describe('owner recovery', () => {
  beforeEach(() => vi.clearAllMocks())

  it('is offered to a super admin only when every owner is suspended', () => {
    vi.mocked(useOrganizationUsers).mockReturnValue(users([suspendedOwner]))
    const { rerender } = render(
      <OrganizationUsersSection tenantId="t1" orgName="Acme" canManage canRecover />
    )
    expect(screen.getByRole('button', { name: /recover ownership/i })).toBeInTheDocument()

    rerender(<OrganizationUsersSection tenantId="t1" orgName="Acme" canManage canRecover={false} />)
    expect(screen.queryByRole('button', { name: /recover ownership/i })).toBeNull()

    vi.mocked(useOrganizationUsers).mockReturnValue(
      users([suspendedOwner, { ...suspendedOwner, user_id: 'u2', status: 'active' }])
    )
    rerender(<OrganizationUsersSection tenantId="t1" orgName="Acme" canManage canRecover />)
    expect(screen.queryByRole('button', { name: /recover ownership/i })).toBeNull()
  })

  it('needs an email, a reason and a code, and sends them with recovery', async () => {
    const user = userEvent.setup()
    vi.mocked(useOrganizationUsers).mockReturnValue(users([suspendedOwner]))
    vi.mocked(recoverOrganizationOwner).mockResolvedValue({
      user: { id: 'n', email: 'new@acme.test', name: '' },
      membership_id: 'm',
      role: 'owner',
      email_sent: true,
    })
    render(<OrganizationUsersSection tenantId="t1" orgName="Acme" canManage canRecover />)
    await user.click(screen.getByRole('button', { name: /recover ownership/i }))

    const confirm = screen.getByRole('button', { name: /create the new owner/i })
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText(/new owner email/i), 'new@acme.test')
    await user.type(screen.getByLabelText(/^reason$/i), 'short')
    await user.type(screen.getByLabelText(/code from your authenticator/i), '123456')
    expect(confirm).toBeDisabled() // reason too short
    await user.type(screen.getByLabelText(/^reason$/i), ' - support case 4411')
    expect(confirm).toBeEnabled()
    await user.click(confirm)

    await waitFor(() =>
      expect(recoverOrganizationOwner).toHaveBeenCalledWith('t1', {
        email: 'new@acme.test',
        name: '',
        reason: 'short - support case 4411',
        totp_code: '123456',
      })
    )
  })
})

describe('AdminConfirmDialog', () => {
  it('shows the API refusal, keeps the dialog open and clears the used code', async () => {
    const user = userEvent.setup()
    const onConfirm = vi
      .fn()
      .mockRejectedValue(new AdminApiError('Invalid or already used code', 401))
    const onOpenChange = vi.fn()
    render(
      <AdminConfirmDialog
        open
        onOpenChange={onOpenChange}
        title="Do it"
        description="What happens"
        confirmLabel="Confirm"
        requireCode
        onConfirm={onConfirm}
      />
    )
    await user.type(screen.getByLabelText(/^reason$/i), 'A good enough reason')
    const code = screen.getByLabelText(/code from your authenticator/i)
    await user.type(code, '12ab3456') // digits only
    expect(code).toHaveValue('123456')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText('Invalid or already used code')).toBeInTheDocument()
    expect(code).toHaveValue('')
    expect(onOpenChange).not.toHaveBeenCalledWith(false)
  })

  it('does not ask for a code when step-up is not required', () => {
    render(
      <AdminConfirmDialog
        open
        onOpenChange={vi.fn()}
        title="Do it"
        description="What happens"
        confirmLabel="Confirm"
        onConfirm={vi.fn()}
      />
    )
    expect(screen.queryByLabelText(/code from your authenticator/i)).toBeNull()
  })
})
