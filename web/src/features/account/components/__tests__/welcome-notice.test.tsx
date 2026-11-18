import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { WelcomeNotice } from '../welcome-notice'

const localLogoutAction = vi.fn()
vi.mock('@/features/auth/actions/local-auth-actions', () => ({
  localLogoutAction: (...a: unknown[]) => localLogoutAction(...a),
}))
vi.mock('@/features/auth/components/resend-verification', () => ({
  ResendVerification: ({ email }: { email?: string }) => <div>{`resend:${email ?? ''}`}</div>,
}))

/**
 * The account space after a refused refresh names the reason and its one
 * next step (never a bare sign-in page, never a retry loop).
 */
describe('WelcomeNotice', () => {
  beforeEach(() => {
    localLogoutAction.mockReset()
    localLogoutAction.mockResolvedValue(undefined)
  })

  it.each(['sso_required', 'idp_mfa_required'] as const)(
    "%s: signs out, then that organization's identity provider",
    async (notice) => {
      render(<WelcomeNotice notice={notice} org="acme" />)
      expect(screen.getByRole('alert')).toHaveTextContent('acme')
      fireEvent.click(
        screen.getByRole('button', { name: /continue with acme's identity provider/i })
      )
      await waitFor(() => expect(localLogoutAction).toHaveBeenCalledWith('/login?org=acme'))
    }
  )

  it("own_sign_in_required: signs out to sign in with the account's own sign-in", async () => {
    render(<WelcomeNotice notice="own_sign_in_required" org="acme" />)
    expect(screen.getByRole('alert')).toHaveTextContent('acme asks for your own sign-in')
    fireEvent.click(screen.getByRole('button', { name: /sign in with your own account/i }))
    await waitFor(() => expect(localLogoutAction).toHaveBeenCalledWith('/login'))
  })

  it('organization_suspended: says so, with no step to take here', () => {
    render(<WelcomeNotice notice="organization_suspended" org="acme" />)
    expect(screen.getByRole('alert')).toHaveTextContent('acme is suspended')
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('email_not_verified: sends the verification link', () => {
    render(<WelcomeNotice notice="email_not_verified" org="acme" email="person@example.com" />)
    expect(screen.getByText('resend:person@example.com')).toBeInTheDocument()
  })

  it('personal_accounts_blocked: signs out to sign in with a work account', async () => {
    render(<WelcomeNotice notice="personal_accounts_blocked" org="acme" />)
    fireEvent.click(screen.getByRole('button', { name: /sign in with your work account/i }))
    await waitFor(() => expect(localLogoutAction).toHaveBeenCalledWith('/login'))
  })
})
