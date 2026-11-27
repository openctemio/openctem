/**
 * Social / SSO sign-in navigation: a successful start navigates to the provider
 * without an error; a failed start or a non-https URL shows the error in the card.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { toast } from 'sonner'

import { LoginForm } from './login-form'
import { useAuthProviders } from '../api/use-auth-providers'
import { useTenantSSOProviders } from '@/features/sso/api/use-sso-api'

// No per-action timer hop: each hop waits a whole macrotask, which a busy machine stretches.
let user: ReturnType<typeof userEvent.setup>
beforeEach(() => {
  user = userEvent.setup({ delay: null })
})

const initiateSocialLogin = vi.fn()
vi.mock('../actions/social-auth-actions', () => ({
  initiateSocialLogin: (...a: unknown[]) => initiateSocialLogin(...a),
}))
vi.mock('@/features/sso/actions/sso-auth-actions', () => ({ initiateSSOLogin: vi.fn() }))
vi.mock('../api/use-auth-providers')
vi.mock('@/features/sso/api/use-sso-api')
vi.mock('./turnstile-widget', () => ({ TurnstileWidget: () => null }))
vi.mock('sonner', () => ({
  toast: { error: vi.fn(), success: vi.fn(), info: vi.fn(), loading: vi.fn(), dismiss: vi.fn() },
}))

const assign = vi.fn()
const realLocation = window.location

describe('LoginForm social sign-in navigation', () => {
  beforeEach(() => {
    assign.mockReset()
    initiateSocialLogin.mockReset()
    vi.mocked(toast.error).mockClear()
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...realLocation, assign },
    })
    vi.mocked(useAuthProviders).mockReturnValue({
      data: {
        social: { google: true, github: false, microsoft: false },
        sso_env_entra_enabled: false,
      },
    } as ReturnType<typeof useAuthProviders>)
    vi.mocked(useTenantSSOProviders).mockReturnValue({
      data: undefined,
    } as ReturnType<typeof useTenantSSOProviders>)
  })
  afterEach(() => {
    Object.defineProperty(window, 'location', { configurable: true, value: realLocation })
  })

  const click = async () => {
    render(<LoginForm />)
    await user.click(screen.getAllByRole('button', { name: /Google/ })[0])
  }

  it('navigates to the provider and shows no error', async () => {
    initiateSocialLogin.mockResolvedValue({ ok: true, url: 'https://accounts.example/auth' })
    await click()
    await waitFor(() => expect(assign).toHaveBeenCalledWith('https://accounts.example/auth'))
    expect(screen.queryByTestId('login-notice')).not.toBeInTheDocument()
    expect(toast.error).not.toHaveBeenCalled()
  })

  it('shows the error when the backend cannot start the sign-in', async () => {
    initiateSocialLogin.mockResolvedValue({ ok: false })
    await click()
    expect(await screen.findByTestId('login-notice')).toHaveTextContent(
      'Could not sign in with Google. Try again.'
    )
    expect(assign).not.toHaveBeenCalled()
  })

  it('refuses a non-https URL', async () => {
    initiateSocialLogin.mockResolvedValue({ ok: true, url: 'javascript:alert(1)' })
    await click()
    expect(await screen.findByTestId('login-notice')).toHaveTextContent(
      'Could not sign in with Google. Try again.'
    )
    expect(assign).not.toHaveBeenCalled()
  })
})
