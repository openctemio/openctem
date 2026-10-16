import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { adminFetch, ADMIN_STEP_UP_HEADER } from '../api/admin-client'
import { AdminStepUpPrompt } from '../components/admin-step-up-prompt'

const FACTORS = {
  webauthn_enabled: true,
  authenticators: [
    {
      id: 'k1',
      name: 'Blue key',
      transports: ['usb'],
      synced: false,
      sync_capable: false,
      created_at: '2026-10-01T00:00:00Z',
    },
  ],
  recovery_codes_left: 10,
  totp_enabled: true,
  totp_allowed: true,
  require_webauthn: false,
  enrollment_required: false,
  min_authenticators: 2,
  max_authenticators: 10,
}

type Call = { url: string; method: string; headers: Record<string, string>; body?: unknown }
let calls: Call[] = []
let protectedAnswers: Response[] = []
let factors: unknown = FACTORS

function route(url: string, init: RequestInit): Response {
  const method = init.method ?? 'GET'
  calls.push({ url, method, headers: init.headers as Record<string, string>, body: init.body })
  const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status })
  if (url.endsWith('/auth/factors')) return json(factors)
  if (url.endsWith('/auth/step-up/webauthn/options'))
    return json({ publicKey: { challenge: 'AQ' } })
  if (url.endsWith('/auth/step-up/webauthn')) return new Response(null, { status: 204 })
  return protectedAnswers.shift() ?? json({ ok: true })
}

const credGet = vi.fn()

function renderPrompt() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <AdminStepUpPrompt />
    </SWRConfig>
  )
}

const stepUpRequired = () =>
  new Response(JSON.stringify({ code: 'ADMIN_STEP_UP_REQUIRED', message: 'Confirm' }), {
    status: 401,
  })

describe('step-up with a security key', () => {
  beforeEach(() => {
    calls = []
    protectedAnswers = []
    factors = FACTORS
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string, init: RequestInit) => Promise.resolve(route(url, init)))
    )
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {})
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: { get: credGet, create: vi.fn() },
    })
    credGet.mockReset()
  })
  afterEach(() => vi.unstubAllGlobals())

  it('offers the key first and retries the action without the header', async () => {
    const user = userEvent.setup()
    renderPrompt()
    protectedAnswers.push(
      stepUpRequired(),
      new Response(JSON.stringify({ id: 'a2' }), { status: 201 })
    )
    credGet.mockResolvedValueOnce({ toJSON: () => ({ id: 'k1' }) })

    const result = adminFetch('/administrators', {
      method: 'POST',
      body: { email: 'x@example.com' },
    })
    const key = await screen.findByRole('button', { name: 'Use security key or passkey' })
    expect(
      screen.getByRole('button', { name: 'Use a code from your authenticator app instead' })
    ).toBeInTheDocument()
    await user.click(key)
    await expect(result).resolves.toEqual({ id: 'a2' })

    const writes = calls.filter((c) => c.url.endsWith('/administrators'))
    expect(writes).toHaveLength(2)
    expect(writes[1].headers[ADMIN_STEP_UP_HEADER]).toBeUndefined()
    expect(writes[1].body).toBe(JSON.stringify({ email: 'x@example.com' }))
    const stepUp = calls.find((c) => c.url.endsWith('/auth/step-up/webauthn'))
    expect(stepUp?.body).toBe(JSON.stringify({ id: 'k1' }))
  })

  it('keeps the authenticator code as the fallback', async () => {
    const user = userEvent.setup()
    renderPrompt()
    protectedAnswers.push(stepUpRequired(), new Response(null, { status: 204 }))
    const result = adminFetch('/platform-idp', { method: 'DELETE' })
    await user.click(
      await screen.findByRole('button', { name: 'Use a code from your authenticator app instead' })
    )
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    await result
    const writes = calls.filter((c) => c.url.endsWith('/platform-idp'))
    expect(writes[1].headers[ADMIN_STEP_UP_HEADER]).toBe('123456')
    expect(credGet).not.toHaveBeenCalled()
  })

  it('WEBAUTHN_REQUIRED goes straight to the key, without the code fallback', async () => {
    renderPrompt()
    protectedAnswers.push(
      new Response(JSON.stringify({ code: 'WEBAUTHN_REQUIRED', message: 'key' }), { status: 403 })
    )
    const result = adminFetch('/platform-idp', { method: 'DELETE' }).catch((e: unknown) => e)
    expect(
      await screen.findByRole('button', { name: 'Use security key or passkey' })
    ).toBeInTheDocument()
    expect(screen.getByText(/authenticator app is not accepted/)).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Use a code from your authenticator app instead' })
    ).not.toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Cancel' }))
    expect(await result).toMatchObject({ code: 'WEBAUTHN_REQUIRED' })
  })

  it('a cancelled key prompt keeps the dialog open with a message', async () => {
    const user = userEvent.setup()
    renderPrompt()
    protectedAnswers.push(stepUpRequired())
    credGet.mockRejectedValueOnce(new DOMException('x', 'NotAllowedError'))
    void adminFetch('/platform-idp', { method: 'DELETE' }).catch(() => undefined)
    await user.click(await screen.findByRole('button', { name: 'Use security key or passkey' }))
    expect(await screen.findByText(/closed or timed out/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Use security key or passkey' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
  })

  it('an administrator without keys gets the code prompt', async () => {
    factors = { ...FACTORS, authenticators: [] }
    renderPrompt()
    protectedAnswers.push(stepUpRequired())
    const result = adminFetch('/platform-idp', { method: 'DELETE' }).catch((e: unknown) => e)
    expect(await screen.findByLabelText('Code from your authenticator')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Use security key or passkey' })
    ).not.toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Cancel' }))
    await result
  })

  it('a form without a code and an administrator without keys: no dialog, the form shows the refusal', async () => {
    factors = { ...FACTORS, authenticators: [] }
    renderPrompt()
    protectedAnswers.push(
      new Response(JSON.stringify({ code: 'STEP_UP_REQUIRED', message: 'Enter a code' }), {
        status: 401,
      })
    )
    const err = await adminFetch('/settings/legal', {
      method: 'PUT',
      body: { totp_code: '' },
    }).catch((e: unknown) => e)
    expect(err).toMatchObject({ code: 'STEP_UP_REQUIRED' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })
})
