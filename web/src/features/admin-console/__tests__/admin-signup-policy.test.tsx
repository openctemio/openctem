import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { SignupPolicyResponse } from '@/lib/api/generated'
import { AdminApiError } from '../api/admin-client'
import { saveSignupPolicy } from '../api/use-signup-policy'
import { SignupPolicyForm } from '../components/signup-policy-form'

vi.mock('../api/use-signup-policy', async (orig) => ({
  ...(await orig<typeof import('../api/use-signup-policy')>()),
  saveSignupPolicy: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const SEEDED: SignupPolicyResponse = {
  mode: 'admin_only',
  request_access: false,
  version: 1,
  source: 'environment',
  updated_at: '2026-10-08T09:00:00Z',
  deployment_mode: 'open',
  self_service_locked: false,
  effective_mode: 'admin_only',
  accounts: 'closed',
  max_accounts: 'open',
  effective_accounts: 'closed',
}

const LOCKED: SignupPolicyResponse = {
  ...SEEDED,
  deployment_mode: 'disabled',
  self_service_locked: true,
  max_accounts: 'closed',
}

describe('SignupPolicyForm', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the stored policy and where it came from', () => {
    render(<SignupPolicyForm policy={SEEDED} canEdit onSaved={vi.fn()} />)
    expect(screen.getByRole('radio', { name: /only platform administrators/i })).toBeChecked()
    expect(screen.getByText(/set from the server configuration at install/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('under SIGNUP_MODE=disabled self-service is locked and the reason is shown', () => {
    render(<SignupPolicyForm policy={LOCKED} canEdit onSaved={vi.fn()} />)
    expect(screen.getByText(/SIGNUP_MODE: disabled/)).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /anyone who signs up/i })).toBeDisabled()
    expect(screen.getByText(/set SIGNUP_MODE=open on the server/i)).toBeInTheDocument()
  })

  it('a stored policy above the ceiling shows what is in force', () => {
    render(
      <SignupPolicyForm
        policy={{ ...LOCKED, mode: 'self_service', effective_mode: 'admin_only' }}
        canEdit
        onSaved={vi.fn()}
      />
    )
    expect(screen.getByText(/limited by the server configuration/i)).toBeInTheDocument()
  })

  it('domain sign-up is offered up to the ceiling, and organizations need open sign-up', async () => {
    const user = userEvent.setup()
    render(
      <SignupPolicyForm
        policy={{
          ...SEEDED,
          deployment_mode: 'domain',
          max_accounts: 'domain',
          self_service_locked: true,
        }}
        canEdit
        onSaved={vi.fn()}
      />
    )
    expect(screen.getByRole('radio', { name: /^anyone(?! who)/i })).toBeDisabled()
    await user.click(screen.getByRole('radio', { name: /verified domain/i }))
    expect(screen.getByRole('radio', { name: /anyone who signs up/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
  })

  it('a read-only administrator cannot change it', () => {
    render(<SignupPolicyForm policy={SEEDED} canEdit={false} onSaved={vi.fn()} />)
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /anyone who signs up/i })).toBeDisabled()
    expect(screen.getByText(/only a super admin can change it/i)).toBeInTheDocument()
  })

  it('saves with the authenticator code and the version it read', async () => {
    const user = userEvent.setup()
    const onSaved = vi.fn()
    vi.mocked(saveSignupPolicy).mockResolvedValue({ ...SEEDED, mode: 'self_service', version: 2 })
    render(<SignupPolicyForm policy={SEEDED} canEdit onSaved={onSaved} />)

    await user.click(screen.getByRole('radio', { name: /^anyone(?! who)/i }))
    await user.click(screen.getByRole('radio', { name: /anyone who signs up/i }))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    const confirm = screen.getByRole('button', { name: 'Confirm' })
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText(/code from your authenticator/i), '123456')
    await user.click(confirm)

    await waitFor(() =>
      expect(saveSignupPolicy).toHaveBeenCalledWith({
        mode: 'self_service',
        accounts: 'open',
        request_access: false,
        version: 1,
        totp_code: '123456',
      })
    )
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
  })

  it('a wrong code keeps the dialog open with the reason', async () => {
    const user = userEvent.setup()
    vi.mocked(saveSignupPolicy).mockImplementation(() =>
      Promise.reject(new AdminApiError('Invalid or already used code', 401))
    )
    render(<SignupPolicyForm policy={SEEDED} canEdit onSaved={vi.fn()} />)
    await user.click(screen.getByRole('switch'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(screen.getByLabelText(/code from your authenticator/i), '000000')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText(/invalid or already used code/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument()
  })

  it('a concurrent change reloads the latest value', async () => {
    const user = userEvent.setup()
    const onSaved = vi.fn()
    vi.mocked(saveSignupPolicy).mockImplementation(() =>
      Promise.reject(new AdminApiError('changed', 409))
    )
    render(<SignupPolicyForm policy={SEEDED} canEdit onSaved={onSaved} />)
    await user.click(screen.getByRole('switch'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(screen.getByLabelText(/code from your authenticator/i), '123456')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
  })
})
