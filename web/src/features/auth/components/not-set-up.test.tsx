/**
 * The sign-up policy's refusal: every refused sign-up (email, Google,
 * Microsoft, GitHub) lands on one page that names no organization and says
 * nothing about the email.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { en, vi as vi_ } from '@/lib/i18n/dictionaries'
import { PUBLIC_ROUTES } from '@/lib/middleware/config'
import { NOT_SET_UP_PATH, SIGNUP_NOT_AVAILABLE, isSignupNotAvailable } from '../lib/signup-outcome'
import { NotSetUpNotice } from './not-set-up-notice'
import { RegisterForm } from './register-form'
import { registerAction } from '../actions/local-auth-actions'
import { useAuthProviders } from '../api/use-auth-providers'

const push = vi.fn()
vi.mock('../api/use-auth-providers')
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push }),
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('../actions/local-auth-actions', () => ({ registerAction: vi.fn() }))
vi.mock('../actions/social-auth-actions', () => ({ initiateSocialLogin: vi.fn() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('not set up page', () => {
  it('has en and vi text and opens without a session', () => {
    for (const key of ['auth.notSetUp.title', 'auth.notSetUp.body', 'auth.notSetUp.backToSignIn']) {
      expect((en as Record<string, string>)[key], key).toBeTruthy()
      expect((vi_ as Record<string, string>)[key], key).toBeTruthy()
    }
    expect(PUBLIC_ROUTES).toContain(NOT_SET_UP_PATH)
  })

  it('names no organization and offers the way back', () => {
    vi.mocked(useAuthProviders).mockReturnValue({
      data: { social: {}, request_access: false },
    } as unknown as ReturnType<typeof useAuthProviders>)
    render(<NotSetUpNotice />)
    expect(screen.queryByRole('link', { name: /request access/i })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /isn't set up yet/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /back to sign in/i })).toHaveAttribute('href', '/login')
  })

  it('offers to request access when the platform takes requests', () => {
    vi.mocked(useAuthProviders).mockReturnValue({
      data: { social: {}, request_access: true },
    } as unknown as ReturnType<typeof useAuthProviders>)
    render(<NotSetUpNotice />)
    expect(screen.getByRole('link', { name: /request access/i })).toHaveAttribute(
      'href',
      '/request-access'
    )
  })

  it('recognizes only the API refusal code', () => {
    expect(isSignupNotAvailable(SIGNUP_NOT_AVAILABLE)).toBe(true)
    for (const other of ['FORBIDDEN', '', undefined, null, 'signup_not_available']) {
      expect(isSignupNotAvailable(other)).toBe(false)
    }
  })
})

describe('RegisterForm on a refused sign-up', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useAuthProviders).mockReturnValue({
      data: { social: { google: false, github: false, microsoft: false } },
    } as unknown as ReturnType<typeof useAuthProviders>)
  })

  it('goes to the not set up page', async () => {
    vi.mocked(registerAction).mockResolvedValue({
      success: false,
      error: 'Your organization is not set up yet.',
      code: SIGNUP_NOT_AVAILABLE,
    })
    const user = userEvent.setup()
    render(<RegisterForm />)
    await user.type(screen.getByLabelText(/first name/i), 'Ann')
    await user.type(screen.getByLabelText(/last name/i), 'Lee')
    await user.type(screen.getByLabelText(/email/i), 'ann@example.com')
    const pw = screen.getAllByLabelText(/password/i)
    for (const input of pw) await user.type(input, 'Str0ngPassw0rd!')
    const checkbox = screen.queryByRole('checkbox')
    if (checkbox) await user.click(checkbox)
    await user.click(screen.getByRole('button', { name: /create account|sign up|register/i }))
    await waitFor(() => expect(push).toHaveBeenCalledWith(NOT_SET_UP_PATH))
  })
})
