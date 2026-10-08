import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { runPlatformUserAction } from '../api/use-platform-users'
import { AdminApiError } from '../api/admin-client'
import { PlatformUserActions } from '../components/platform-user-actions'
import { PlatformUserBadges } from '../components/platform-user-badges'
import type { PlatformUserDetail } from '../types'

vi.mock('../api/use-platform-users', async (orig) => ({
  ...(await orig<typeof import('../api/use-platform-users')>()),
  runPlatformUserAction: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function account(patch: Partial<PlatformUserDetail> = {}): PlatformUserDetail {
  return {
    id: 'u1',
    email: 'person@corp.test',
    name: 'Person',
    status: 'active',
    auth_provider: 'local',
    email_verified: true,
    locked: false,
    failed_logins: 0,
    created_at: '2026-10-01T00:00:00Z',
    memberships: 1,
    mfa_enabled: false,
    is_platform_admin: false,
    erased: false,
    membership_list: [],
    identities: [],
    sessions: [
      {
        id: 's1',
        auth_method: 'password',
        created_at: '2026-10-08T00:00:00Z',
        last_activity_at: '2026-10-08T01:00:00Z',
        expires_at: '2026-10-09T00:00:00Z',
      },
    ],
    ...patch,
  }
}

const names = () => screen.queryAllByRole('button').map((b) => b.textContent)

describe('PlatformUserActions', () => {
  beforeEach(() => vi.clearAllMocks())

  it('offers only the actions that apply to the account', () => {
    const { rerender } = render(<PlatformUserActions user={account()} onDone={vi.fn()} />)
    expect(names()).toEqual(['Sign out everywhere', 'Send password reset'])

    rerender(
      <PlatformUserActions
        user={account({
          locked: true,
          failed_logins: 5,
          email_verified: false,
          auth_provider: 'oidc',
          sessions: [],
        })}
        onDone={vi.fn()}
      />
    )
    expect(names()).toEqual(['Unlock', 'Resend verification'])
  })

  it('disables every action for a platform administrator account', () => {
    render(<PlatformUserActions user={account({ is_platform_admin: true })} onDone={vi.fn()} />)
    for (const b of screen.getAllByRole('button')) expect(b).toBeDisabled()
    expect(screen.getByText(/manage it in Security > Administrators/)).toBeInTheDocument()
  })

  it('asks for a reason and sends it with the action', async () => {
    const user = userEvent.setup()
    const onDone = vi.fn()
    vi.mocked(runPlatformUserAction).mockResolvedValue({ status: 'sessions_revoked' })
    render(<PlatformUserActions user={account()} onDone={onDone} />)
    await user.click(screen.getByRole('button', { name: 'Sign out everywhere' }))
    expect(screen.queryByLabelText(/code from your authenticator/i)).toBeNull()
    const dialogButtons = screen.getAllByRole('button', { name: 'Sign out everywhere' })
    const confirm = dialogButtons[dialogButtons.length - 1]
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText(/^reason$/i), 'Support case 4411: lost laptop')
    await user.click(confirm)
    await waitFor(() =>
      expect(runPlatformUserAction).toHaveBeenCalledWith(
        'u1',
        'revoke-sessions',
        'Support case 4411: lost laptop'
      )
    )
    await waitFor(() => expect(onDone).toHaveBeenCalled())
  })

  it('shows the refusal from the API', async () => {
    const user = userEvent.setup()
    vi.mocked(runPlatformUserAction).mockRejectedValue(
      new AdminApiError('No email can be sent from this installation; configure SMTP first.', 409)
    )
    render(<PlatformUserActions user={account()} onDone={vi.fn()} />)
    await user.click(screen.getByRole('button', { name: 'Send password reset' }))
    await user.type(screen.getByLabelText(/^reason$/i), 'User asked by phone, ticket 99')
    const buttons = screen.getAllByRole('button', { name: 'Send password reset' })
    await user.click(buttons[buttons.length - 1])
    expect(await screen.findByText(/configure SMTP first/)).toBeInTheDocument()
  })
})

describe('PlatformUserBadges', () => {
  it('shows the sign-in state', () => {
    render(
      <PlatformUserBadges
        user={account({ locked: true, email_verified: false, mfa_enabled: true })}
      />
    )
    expect(screen.getByText('Locked')).toBeInTheDocument()
    expect(screen.getByText('Email not verified')).toBeInTheDocument()
    expect(screen.getByText('MFA')).toBeInTheDocument()
  })
})
