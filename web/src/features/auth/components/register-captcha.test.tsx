/**
 * The sign-up form renders the Turnstile check when the API reports a site
 * key, and does not submit without a token. Without a site key the form is
 * unchanged.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { RegisterForm } from './register-form'
import { useAuthProviders } from '../api/use-auth-providers'
import { registerAction } from '../actions/local-auth-actions'
import { toast } from 'sonner'

vi.mock('../api/use-auth-providers')
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('../actions/local-auth-actions', () => ({ registerAction: vi.fn() }))
vi.mock('../actions/social-auth-actions', () => ({ initiateSocialLogin: vi.fn() }))
vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))

function providers(captcha_site_key?: string) {
  vi.mocked(useAuthProviders).mockReturnValue({
    data: { social: {}, captcha_site_key },
  } as unknown as ReturnType<typeof useAuthProviders>)
}

async function fillAndSubmit() {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText(/first name/i), 'Ada')
  await user.type(screen.getByLabelText(/last name/i), 'Lovelace')
  await user.type(screen.getByLabelText(/^email/i), 'ada@example.com')
  const pw = screen.getAllByLabelText(/password/i)
  await user.type(pw[0], 'Zr7uqLakeTunnel41')
  await user.type(pw[1], 'Zr7uqLakeTunnel41')
  await user.click(screen.getByRole('button', { name: /create account/i }))
}

describe('RegisterForm CAPTCHA', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the security check and refuses to submit without a token', async () => {
    providers('site-key-1')
    render(<RegisterForm />)
    expect(screen.getByRole('group', { name: 'Security check' })).toBeInTheDocument()
    await fillAndSubmit()
    expect(toast.error).toHaveBeenCalledWith('Complete the security check first.')
    expect(registerAction).not.toHaveBeenCalled()
  })

  it('has no security check when the API reports no site key', () => {
    providers(undefined)
    render(<RegisterForm />)
    expect(screen.queryByRole('group', { name: 'Security check' })).toBeNull()
  })
})
