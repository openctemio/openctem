import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const start = vi.fn()
const verify = vi.fn()
vi.mock('@/features/admin-console/api/use-admin-session', () => ({
  adminStartSession: (...a: unknown[]) => start(...a),
  adminVerifyMFA: (...a: unknown[]) => verify(...a),
  adminIdPInfo: () => Promise.resolve({ enabled: false }),
  adminIdPStart: vi.fn(),
}))
vi.mock('@/features/auth/actions/local-auth-actions', () => ({ localLogoutAction: vi.fn() }))

import AdminVerifyPage from '@/app/(admin-console)/admin/login/page'
import { AdminApiError } from '@/features/admin-console/api/admin-client'

const originalLocation = window.location
const ADMIN = { id: 'a1', email: 'admin@example.com', name: 'A', role: 'super_admin' }

function stubLocation() {
  const href = vi.fn()
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: {
      ...originalLocation,
      search: '',
      replace: vi.fn(),
      set href(v: string) {
        href(v)
      },
    },
  })
  return href
}

const fetchMock = vi.fn()
const credGet = vi.fn()

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status })
}

describe('console sign-in: security key first', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {})
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: { get: credGet, create: vi.fn() },
    })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation })
  })

  it('offers the key first and signs in with its answer', async () => {
    const href = stubLocation()
    const user = userEvent.setup()
    start.mockResolvedValueOnce({
      status: 'mfa_required',
      methods: ['webauthn', 'totp', 'recovery_code'],
    })
    fetchMock
      .mockResolvedValueOnce(json({ publicKey: { challenge: 'AQ', userVerification: 'required' } }))
      .mockResolvedValueOnce(json(ADMIN))
    credGet.mockResolvedValueOnce({ toJSON: () => ({ id: 'cred-1', type: 'public-key' }) })

    render(<AdminVerifyPage />)
    const button = await screen.findByRole('button', { name: 'Use security key or passkey' })
    expect(button).toHaveFocus()
    expect(screen.getByRole('button', { name: 'Use authenticator app' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Use a recovery code' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Verification code')).not.toBeInTheDocument()

    await user.click(button)
    await waitFor(() => expect(href).toHaveBeenCalledWith('/admin'))
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/admin/auth/webauthn/session/options')
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/admin/auth/webauthn/session')
    expect(fetchMock.mock.calls[1][1].body).toBe(
      JSON.stringify({ id: 'cred-1', type: 'public-key' })
    )
    const challenge = credGet.mock.calls[0][0].publicKey.challenge as ArrayBuffer
    expect(new Uint8Array(challenge)).toEqual(new Uint8Array([1]))
  })

  it('a cancelled key prompt leaves the administrator on the step with a message', async () => {
    const href = stubLocation()
    const user = userEvent.setup()
    start.mockResolvedValueOnce({ status: 'mfa_required', methods: ['webauthn', 'recovery_code'] })
    fetchMock.mockResolvedValueOnce(json({ publicKey: { challenge: 'AQ' } }))
    credGet.mockRejectedValueOnce(new DOMException('cancelled', 'NotAllowedError'))

    render(<AdminVerifyPage />)
    await user.click(await screen.findByRole('button', { name: 'Use security key or passkey' }))
    expect(await screen.findByText(/closed or timed out/)).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(href).not.toHaveBeenCalled()
    // The policy took the authenticator app away: no link to it.
    expect(screen.queryByRole('button', { name: 'Use authenticator app' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Use security key or passkey' })).toBeEnabled()
  })

  it('signs in with a recovery code', async () => {
    const href = stubLocation()
    const user = userEvent.setup()
    start.mockResolvedValueOnce({
      status: 'mfa_required',
      methods: ['webauthn', 'totp', 'recovery_code'],
    })
    fetchMock.mockResolvedValueOnce(json(ADMIN))

    render(<AdminVerifyPage />)
    await user.click(await screen.findByRole('button', { name: 'Use a recovery code' }))
    await user.type(screen.getByLabelText('Recovery code'), 'abcd-efgh-ijkl')
    await user.click(screen.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(href).toHaveBeenCalledWith('/admin'))
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/admin/auth/recovery')
    expect(fetchMock.mock.calls[0][1].body).toBe(JSON.stringify({ code: 'abcd-efgh-ijkl' }))
  })

  it('a refused recovery code shows the error and clears the field', async () => {
    stubLocation()
    const user = userEvent.setup()
    start.mockResolvedValueOnce({ status: 'mfa_required', methods: ['totp', 'recovery_code'] })
    fetchMock.mockResolvedValueOnce(
      json({ message: 'Invalid or already used recovery code', code: 'UNAUTHORIZED' }, 401)
    )
    render(<AdminVerifyPage />)
    await user.click(await screen.findByRole('button', { name: 'Use a recovery code' }))
    await user.type(screen.getByLabelText('Recovery code'), 'used-code')
    await user.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText('Invalid or already used recovery code')).toBeInTheDocument()
    expect(screen.getByLabelText('Recovery code')).toHaveValue('')
  })

  it('switches to the key when the console refuses the authenticator code', async () => {
    stubLocation()
    const user = userEvent.setup()
    // The IdP callback and older answers carry no methods: TOTP first.
    start.mockResolvedValueOnce({ status: 'mfa_required' })
    verify.mockRejectedValueOnce(
      new AdminApiError('Use your security key or passkey', 403, 'WEBAUTHN_REQUIRED')
    )
    render(<AdminVerifyPage />)
    await user.type(await screen.findByLabelText('Verification code'), '123456')
    await user.click(screen.getByRole('button', { name: 'Continue' }))
    expect(
      await screen.findByRole('button', { name: 'Use security key or passkey' })
    ).toBeInTheDocument()
    expect(screen.getByText(/The authenticator app is not accepted/)).toBeInTheDocument()
    expect(screen.queryByLabelText('Verification code')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Use authenticator app' })).not.toBeInTheDocument()
  })

  it('without WebAuthn in the browser it starts on the authenticator app', async () => {
    stubLocation()
    vi.stubGlobal('PublicKeyCredential', undefined)
    start.mockResolvedValueOnce({
      status: 'mfa_required',
      methods: ['webauthn', 'totp', 'recovery_code'],
    })
    render(<AdminVerifyPage />)
    expect(await screen.findByLabelText('Verification code')).toBeInTheDocument()
  })
})
