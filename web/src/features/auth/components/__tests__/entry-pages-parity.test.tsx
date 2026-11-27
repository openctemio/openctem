/**
 * The entry pages moved onto the entry card parts. This file holds what must
 * not move with them: each page and state has exactly one h1, a notice keeps
 * the role it is announced with, and every field keeps the attributes password
 * managers and one-time-code autofill read.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import ForgotPasswordPage from '@/app/(auth)/forgot-password/page'
import { DeviceCodeView } from '@/features/mcp-oauth/components/device-code-view'

import {
  confirmAccessRequestAction,
  startSessionMfaAction,
  verifyEmailAction,
} from '../../actions/local-auth-actions'
import {
  useAuthProviders,
  useEmailUnavailable,
  usePasswordPolicy,
} from '../../api/use-auth-providers'
import { NotSetUpNotice } from '../not-set-up-notice'
import { PasswordTokenForm } from '../password-token-form'
import { RegisterGate } from '../register-gate'
import { RequestAccessConfirm } from '../request-access-confirm'
import { RequestAccessForm } from '../request-access-form'
import { TwoFactorSetup } from '../two-factor-setup'
import { VerifyEmail } from '../verify-email'

vi.mock('../../api/use-auth-providers')
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('../../actions/local-auth-actions', () => ({
  registerAction: vi.fn(),
  forgotPasswordAction: vi.fn(),
  resetPasswordAction: vi.fn(),
  verifyEmailAction: vi.fn(),
  submitAccessRequestAction: vi.fn(),
  confirmAccessRequestAction: vi.fn(),
  startSessionMfaAction: vi.fn(),
  localLogoutAction: vi.fn(),
}))
vi.mock('../../actions/social-auth-actions', () => ({ initiateSocialLogin: vi.fn() }))
vi.mock('@/lib/api/client', () => ({ post: vi.fn() }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'Example Corp' } }),
}))
vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

// The checkbox measures itself with ResizeObserver, which jsdom lacks.
vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
)

function providers(extra: Record<string, unknown> = {}) {
  vi.mocked(useAuthProviders).mockReturnValue({
    data: {
      social: { google: true, github: true, microsoft: true },
      registration_enabled: true,
      ...extra,
    },
    isLoading: false,
  } as unknown as ReturnType<typeof useAuthProviders>)
  vi.mocked(useEmailUnavailable).mockReturnValue(false)
  vi.mocked(usePasswordPolicy).mockReturnValue(undefined)
}

const h1s = () => screen.getAllByRole('heading', { level: 1 })

/** The attributes a browser or password manager reads from a field. */
function attrs(el: HTMLElement) {
  return {
    type: el.getAttribute('type'),
    autocomplete: el.getAttribute('autocomplete'),
    name: el.getAttribute('name'),
    id: el.getAttribute('id'),
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  providers()
  window.location.hash = ''
})

describe('one h1 per entry page and state', () => {
  it('register: open, closed', () => {
    const { unmount } = render(<RegisterGate />)
    expect(h1s().map((h) => h.textContent)).toEqual(['Create an account'])
    unmount()

    providers({ registration_enabled: false })
    render(<RegisterGate />)
    expect(h1s().map((h) => h.textContent)).toEqual(['Registration is disabled'])
  })

  it('forgot password: form, no e-mail on this server', () => {
    const { unmount } = render(<ForgotPasswordPage />)
    expect(h1s().map((h) => h.textContent)).toEqual(['Forgot password'])
    unmount()

    vi.mocked(useEmailUnavailable).mockReturnValue(true)
    render(<ForgotPasswordPage />)
    expect(h1s()).toHaveLength(1)
  })

  it.each([
    ['reset', 'tok', 'Reset password'],
    ['setup', 'tok', 'Set your password'],
    ['reset', '', 'This reset link does not work'],
    ['setup', '', 'This setup link does not work'],
  ] as const)('password link (%s, token "%s")', (mode, token, title) => {
    render(<PasswordTokenForm mode={mode} token={token} />)
    expect(h1s().map((h) => h.textContent)).toEqual([title])
  })

  it('verify email: checking, then the outcome', async () => {
    window.location.hash = '#token=synthetic'
    vi.mocked(verifyEmailAction).mockResolvedValue({ success: false, error: 'expired' })
    render(<VerifyEmail />)
    expect(h1s()).toHaveLength(1)
    await waitFor(() =>
      expect(screen.getByText('This verification link does not work')).toBeInTheDocument()
    )
    expect(h1s()).toHaveLength(1)
  })

  it('request access: form and confirmation', async () => {
    const { unmount } = render(<RequestAccessForm />)
    expect(h1s().map((h) => h.textContent)).toEqual(['Request access'])
    unmount()

    window.location.hash = '#token=synthetic'
    vi.mocked(confirmAccessRequestAction).mockResolvedValue({
      success: true,
      data: null,
      message: 'ok',
    })
    render(<RequestAccessConfirm />)
    expect(h1s()).toHaveLength(1)
    await waitFor(() =>
      expect(
        screen.getByText('Your request is confirmed and waits for an administrator.')
      ).toBeInTheDocument()
    )
  })

  it('not set up', () => {
    render(<NotSetUpNotice />)
    expect(h1s().map((h) => h.textContent)).toEqual(["Your organization isn't set up yet"])
  })

  it('two-factor setup keeps its page title above the step', async () => {
    vi.mocked(startSessionMfaAction).mockResolvedValue({
      success: false,
      error: 'failed',
    } as Awaited<ReturnType<typeof startSessionMfaAction>>)
    render(<TwoFactorSetup />)
    // Neutral until the API says whether it is setup or only a code.
    expect(h1s().map((h) => h.textContent)).toEqual(['Two-factor authentication'])
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(h1s()).toHaveLength(1)
  })

  it('device code', () => {
    render(<DeviceCodeView />)
    expect(h1s().map((h) => h.textContent)).toEqual(['Connect a terminal'])
  })
})

describe('notices keep the role they are announced with', () => {
  it('verify email and request confirmation report their outcome as a status', async () => {
    window.location.hash = '#token=synthetic'
    vi.mocked(verifyEmailAction).mockResolvedValue({ success: true, data: null, message: 'ok' })
    const { unmount } = render(<VerifyEmail />)
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'Your email address is verified. You can sign in.'
      )
    )
    expect(screen.queryByRole('alert')).toBeNull()
    unmount()

    window.location.hash = '#token=synthetic'
    vi.mocked(confirmAccessRequestAction).mockResolvedValue({ success: false, error: 'expired' })
    render(<RequestAccessConfirm />)
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'It may have expired or been used already. Send a new request.'
      )
    )
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('the device code page warns politely: a warning on load is not an error', () => {
    render(<DeviceCodeView />)
    expect(screen.getByRole('status')).toHaveTextContent('Only enter a code you asked for')
    expect(screen.queryByRole('alert')).toBeNull()
  })
})

describe('autofill attributes are as before', () => {
  it('register', () => {
    const { container } = render(<RegisterGate />)
    expect(container.querySelector('form')).toHaveAttribute('method', 'post')
    expect(attrs(screen.getByLabelText('First name'))).toMatchObject({
      autocomplete: 'given-name',
      name: 'firstName',
    })
    expect(attrs(screen.getByLabelText('Last name'))).toMatchObject({
      autocomplete: 'family-name',
      name: 'lastName',
    })
    expect(attrs(screen.getByLabelText('Email'))).toMatchObject({
      type: 'email',
      autocomplete: 'email',
      name: 'email',
    })
    expect(attrs(screen.getByLabelText('Password'))).toMatchObject({
      type: 'password',
      autocomplete: 'new-password',
      name: 'password',
    })
    expect(attrs(screen.getByLabelText('Confirm password'))).toMatchObject({
      type: 'password',
      autocomplete: 'new-password',
      name: 'confirmPassword',
    })
    // Each provider is a button with its name as text.
    for (const name of ['Google', 'GitHub', 'Microsoft']) {
      expect(screen.getByRole('button', { name: new RegExp(name) })).toBeInTheDocument()
    }
  })

  it('forgot password', () => {
    render(<ForgotPasswordPage />)
    expect(attrs(screen.getByLabelText('Email'))).toMatchObject({
      type: 'email',
      autocomplete: 'email',
      name: 'email',
    })
  })

  it.each(['reset', 'setup'] as const)('password link (%s)', (mode) => {
    const { container } = render(<PasswordTokenForm mode={mode} token="tok" />)
    expect(container.querySelector('form')).toHaveAttribute('method', 'post')
    const fields = container.querySelectorAll('input[type="password"]')
    expect(fields).toHaveLength(2)
    expect([...fields].map((f) => f.getAttribute('autocomplete'))).toEqual([
      'new-password',
      'new-password',
    ])
    expect([...fields].map((f) => f.getAttribute('name'))).toEqual(['password', 'confirmPassword'])
    expect(container.querySelector('#reset-revoke-keys') !== null).toBe(mode === 'reset')
  })

  it('verify email resend', async () => {
    vi.mocked(verifyEmailAction).mockResolvedValue({ success: false, error: 'expired' })
    window.location.hash = '#token=synthetic'
    render(<VerifyEmail />)
    const field = await screen.findByLabelText('Email address')
    expect(attrs(field)).toMatchObject({
      type: 'email',
      autocomplete: 'email',
      id: 'resend-verification-email',
    })
  })

  it('request access', () => {
    const { container } = render(<RequestAccessForm />)
    const form = container.querySelector('form')
    expect(form).toHaveAttribute('method', 'post')
    expect(form).toHaveAttribute('novalidate')
    const company = container.querySelector('#ra-company')
    expect(company).toHaveAttribute('autocomplete', 'organization')
    expect(company).toHaveAttribute('maxlength', '200')
    expect(company).toBeRequired()
    const email = container.querySelector('#ra-email')
    expect(email).toHaveAttribute('type', 'email')
    expect(email).toHaveAttribute('autocomplete', 'email')
    expect(email).toBeRequired()
    expect(container.querySelector('#ra-note')).toHaveAttribute('maxlength', '1000')
  })

  it('device code: never offered for autofill, never sent by itself', async () => {
    const { container } = render(<DeviceCodeView />)
    const code = container.querySelector('#device-user-code')
    expect(code).toHaveAttribute('autocomplete', 'off')
    expect(code).toHaveAttribute('autocapitalize', 'characters')
    expect(code).toHaveAttribute('spellcheck', 'false')
    expect(code).toHaveAttribute('inputmode', 'text')
    expect(code).toHaveAttribute('maxlength', '9')
    expect(container.querySelector('form')).toHaveAttribute('novalidate')
    // The button stays enabled; an empty code is explained under the field.
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/8 characters/i)
  })
})
