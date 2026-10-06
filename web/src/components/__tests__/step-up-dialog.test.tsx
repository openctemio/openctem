import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const endSession = vi.hoisted(() => vi.fn())
vi.mock('@/stores/auth-store', async (orig) => ({
  ...(await orig<typeof import('@/stores/auth-store')>()),
  endSessionAndSignIn: endSession,
}))

import { StepUpDialogHost } from '../step-up-dialog'
import { requestStepUp } from '@/lib/api/step-up'

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('StepUpDialogHost', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    endSession.mockReset()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  function stepUpCalls() {
    return fetchMock.mock.calls.filter(
      ([url, init]) =>
        String(url).endsWith('/api/v1/auth/step-up') && (init as RequestInit)?.method === 'POST'
    )
  }

  it('asks for the password, shows a wrong password, and resolves after the right one', async () => {
    const user = userEvent.setup()
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        const body = JSON.parse(String(init.body)) as { password?: string }
        return body.password === 'right'
          ? jsonResponse(200, { valid_until: '2026-10-05T20:00:00Z', window_seconds: 600 })
          : jsonResponse(403, { code: 'STEP_UP_FAILED', message: 'Re-authentication failed' })
      }
      return jsonResponse(200, { method: 'password', window_seconds: 600 })
    })
    render(<StepUpDialogHost />)

    let result: Promise<boolean> = Promise.resolve(false)
    act(() => {
      result = requestStepUp()
    })
    const input = await screen.findByLabelText('Password')

    await user.type(input, 'wrong')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Incorrect password.')

    await user.type(screen.getByLabelText('Password'), 'right')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))

    await expect(result).resolves.toBe(true)
    expect(stepUpCalls()).toHaveLength(2)
    expect(JSON.parse(String((stepUpCalls()[1][1] as RequestInit).body))).toEqual({
      password: 'right',
    })
  })

  it('asks an authenticator account for a 6-digit code and sends it as totp', async () => {
    const user = userEvent.setup()
    fetchMock.mockImplementation(async (_url: string, init?: RequestInit) =>
      init?.method === 'POST'
        ? jsonResponse(200, { valid_until: '2026-10-05T20:00:00Z', window_seconds: 600 })
        : jsonResponse(200, { method: 'totp', window_seconds: 600 })
    )
    render(<StepUpDialogHost />)
    let result: Promise<boolean> = Promise.resolve(false)
    act(() => {
      result = requestStepUp()
    })
    const input = await screen.findByLabelText('Authenticator code')
    const confirm = screen.getByRole('button', { name: 'Confirm' })
    await user.type(input, '12a34')
    expect(confirm).toBeDisabled()
    await user.type(input, '56')
    await user.click(confirm)

    await expect(result).resolves.toBe(true)
    expect(JSON.parse(String((stepUpCalls()[0][1] as RequestInit).body))).toEqual({
      totp: '123456',
    })
  })

  it('cancel resolves false', async () => {
    const user = userEvent.setup()
    fetchMock.mockResolvedValue(jsonResponse(200, { method: 'password', window_seconds: 600 }))
    render(<StepUpDialogHost />)
    let result: Promise<boolean> = Promise.resolve(true)
    act(() => {
      result = requestStepUp()
    })
    await screen.findByLabelText('Password')
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    await expect(result).resolves.toBe(false)
    expect(stepUpCalls()).toHaveLength(0)
  })

  it('an SSO account without an authenticator is sent to sign in again', async () => {
    const user = userEvent.setup()
    fetchMock.mockResolvedValue(jsonResponse(200, { method: 'fresh_sign_in', window_seconds: 600 }))
    render(<StepUpDialogHost />)
    act(() => {
      void requestStepUp()
    })
    await user.click(await screen.findByRole('button', { name: 'Sign in again' }))
    await waitFor(() => expect(endSession).toHaveBeenCalledTimes(1))
    // The identity provider must authenticate the user again, not reuse its session.
    expect(endSession).toHaveBeenCalledWith(expect.any(String), { reauth: true })
    expect(stepUpCalls()).toHaveLength(0)
  })
})
