import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const signIn = vi.fn()
const verify = vi.fn()
const idpInfo = vi.fn()
const idpStart = vi.fn()
vi.mock('@/features/admin-console/api/use-admin-session', () => ({
  adminSignIn: (...a: unknown[]) => signIn(...a),
  adminVerifyMFA: (...a: unknown[]) => verify(...a),
  adminIdPInfo: (...a: unknown[]) => idpInfo(...a),
  adminIdPStart: (...a: unknown[]) => idpStart(...a),
}))

import AdminSignInPage from '@/app/(admin-console)/admin/login/page'
import { AdminApiError } from '@/features/admin-console/api/admin-client'

const originalLocation = window.location

/** Replaces window.location so navigations can be observed. */
function stubLocation(search: string) {
  const nav = { href: vi.fn(), replace: vi.fn(), assign: vi.fn() }
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: {
      ...originalLocation,
      search,
      replace: nav.replace,
      assign: nav.assign,
      set href(v: string) {
        nav.href(v)
      },
    },
  })
  return nav
}

describe('Admin console sign-in (its own, no tenant session)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    idpInfo.mockResolvedValue({ enabled: false })
  })
  afterEach(() => {
    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation })
  })

  async function signInWith(email: string, password: string) {
    const user = userEvent.setup()
    render(<AdminSignInPage />)
    await user.type(screen.getByLabelText('Email'), email)
    await user.type(screen.getByLabelText('Password'), password)
    await user.click(screen.getByRole('button', { name: 'Continue' }))
    return user
  }

  it('asks for the email and password, then the code', async () => {
    stubLocation('')
    signIn.mockResolvedValueOnce({ status: 'mfa_required' })
    await signInWith('ops@acme.io', 'Secret-pass-1')
    expect(signIn).toHaveBeenCalledWith('ops@acme.io', 'Secret-pass-1')
    expect(await screen.findByLabelText('Verification code')).toBeInTheDocument()
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
    expect(screen.queryByRole('img', { name: /QR code/ })).not.toBeInTheDocument()
  })

  it('shows the QR code and setup key on first use', async () => {
    stubLocation('')
    signIn.mockResolvedValueOnce({
      status: 'mfa_enrollment_required',
      otpauth_uri: 'otpauth://totp/OpenCTEM%20Admin:ops@acme.io?secret=ABCDEFGH&issuer=OpenCTEM',
      secret: 'ABCDEFGHIJKLMNOP',
    })
    await signInWith('ops@acme.io', 'Secret-pass-1')
    expect(await screen.findByRole('img', { name: /QR code/ })).toBeInTheDocument()
    expect(screen.getByText('ABCD EFGH IJKL MNOP')).toBeInTheDocument()
  })

  it('one answer for a wrong password, and the password is cleared', async () => {
    const nav = stubLocation('')
    signIn.mockRejectedValueOnce(new AdminApiError('Wrong email or password', 401))
    await signInWith('ops@acme.io', 'nope')
    expect(await screen.findByText('Wrong email or password.')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(nav.replace).not.toHaveBeenCalled()
    expect(nav.href).not.toHaveBeenCalled()
  })

  it('explains a refusal from the API', async () => {
    stubLocation('')
    signIn.mockRejectedValueOnce(
      new AdminApiError('This account is not a platform administrator', 403)
    )
    await signInWith('member@acme.io', 'Secret-pass-1')
    expect(
      await screen.findByText('This account is not a platform administrator')
    ).toBeInTheDocument()
    expect(screen.queryByLabelText('Verification code')).not.toBeInTheDocument()
  })

  it('shows the API error for a wrong code and lets the admin retry or start over', async () => {
    stubLocation('')
    signIn.mockResolvedValueOnce({ status: 'mfa_required' })
    verify.mockRejectedValueOnce(new AdminApiError('Invalid or expired verification code', 401))
    const user = await signInWith('ops@acme.io', 'Secret-pass-1')
    await user.type(await screen.findByLabelText('Verification code'), '000000')
    await user.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText('Invalid or expired verification code')).toBeInTheDocument()
    expect(screen.getByLabelText('Verification code')).toHaveValue('')
    await user.click(screen.getByRole('button', { name: 'Sign in with a different account' }))
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
  })

  it('only follows ?next= into the console (no open redirect)', async () => {
    const nav = stubLocation('?next=https://evil.example')
    signIn.mockResolvedValueOnce({ status: 'mfa_required' })
    verify.mockResolvedValueOnce({
      id: '1',
      email: 'ops@acme.io',
      name: 'Ops',
      role: 'super_admin',
    })
    const user = await signInWith('ops@acme.io', 'Secret-pass-1')
    await user.type(await screen.findByLabelText('Verification code'), '123456')
    await user.click(screen.getByRole('button', { name: 'Continue' }))
    await vi.waitFor(() => expect(nav.href).toHaveBeenCalled())
    expect(nav.href).toHaveBeenCalledWith('/admin')
  })

  it('offers the administrators identity provider next to the password form', async () => {
    const nav = stubLocation('?next=/admin/organizations')
    idpInfo.mockResolvedValueOnce({ enabled: true, display_name: 'Contoso SSO' })
    idpStart.mockResolvedValueOnce({ authorization_url: 'https://idp.example/authorize?x=1' })
    const user = userEvent.setup()
    render(<AdminSignInPage />)
    const button = await screen.findByRole('button', { name: 'Sign in with Contoso SSO' })
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    await user.click(button)
    await vi.waitFor(() =>
      expect(nav.assign).toHaveBeenCalledWith('https://idp.example/authorize?x=1')
    )
    expect(window.sessionStorage.getItem('openctem.admin.next')).toBe('/admin/organizations')
  })

  it('never navigates to a non-http authorization URL', async () => {
    const nav = stubLocation('')
    idpInfo.mockResolvedValueOnce({ enabled: true, display_name: 'SSO' })
    idpStart.mockResolvedValueOnce({ authorization_url: 'javascript:alert(1)' })
    const user = userEvent.setup()
    render(<AdminSignInPage />)
    await user.click(await screen.findByRole('button', { name: 'Sign in with SSO' }))
    await vi.waitFor(() => expect(idpStart).toHaveBeenCalled())
    expect(nav.assign).not.toHaveBeenCalled()
  })

  it('points to the identity provider when it is required', async () => {
    stubLocation('')
    idpInfo.mockResolvedValueOnce({ enabled: true, display_name: 'Contoso SSO' })
    signIn.mockRejectedValueOnce(
      new AdminApiError(
        'Sign in to the admin console with the identity provider',
        403,
        'IDP_SIGN_IN_REQUIRED'
      )
    )
    await signInWith('ops@acme.io', 'Secret-pass-1')
    expect(
      await screen.findByText(/Administrators sign in with the identity provider/)
    ).toBeInTheDocument()
    expect(
      screen.getAllByRole('button', { name: 'Sign in with Contoso SSO' }).length
    ).toBeGreaterThan(0)
    expect(screen.queryByLabelText('Verification code')).not.toBeInTheDocument()
  })
})
