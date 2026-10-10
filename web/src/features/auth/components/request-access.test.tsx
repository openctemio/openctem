import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { en, vi as vi_ } from '@/lib/i18n/dictionaries'
import { PUBLIC_ROUTES } from '@/lib/middleware/config'
import {
  confirmAccessRequestAction,
  submitAccessRequestAction,
} from '../actions/local-auth-actions'
import { RequestAccessConfirm } from './request-access-confirm'
import { RequestAccessForm } from './request-access-form'
import { SIGNUP_NOT_AVAILABLE } from '../lib/signup-outcome'

vi.mock('../actions/local-auth-actions', () => ({
  submitAccessRequestAction: vi.fn(),
  confirmAccessRequestAction: vi.fn(),
}))

describe('request access', () => {
  beforeEach(() => vi.clearAllMocks())

  it('has en and vi text and opens without a session', () => {
    const keys = Object.keys(en).filter((k) => k.startsWith('auth.requestAccess.'))
    expect(keys.length).toBeGreaterThan(5)
    for (const key of keys) expect((vi_ as Record<string, string>)[key], key).toBeTruthy()
    expect(PUBLIC_ROUTES).toContain('/request-access')
  })

  it('sends the form and shows the same thanks whatever happens', async () => {
    vi.mocked(submitAccessRequestAction).mockResolvedValue({
      success: true,
      data: null,
      message: 'x',
    })
    const user = userEvent.setup()
    render(<RequestAccessForm />)
    const send = screen.getByRole('button', { name: /send request/i })
    expect(send).toBeDisabled()
    await user.type(screen.getByLabelText(/company/i), 'Acme')
    await user.type(screen.getByLabelText(/work email/i), 'owner@acme.com')
    await user.click(send)
    await waitFor(() =>
      expect(submitAccessRequestAction).toHaveBeenCalledWith({
        company: 'Acme',
        email: 'owner@acme.com',
        note: '',
      })
    )
    expect(await screen.findByText(/if your request is approved/i)).toBeInTheDocument()
  })

  it('says when requests are closed', async () => {
    vi.mocked(submitAccessRequestAction).mockResolvedValue({
      success: false,
      error: 'no',
      code: SIGNUP_NOT_AVAILABLE,
    })
    const user = userEvent.setup()
    render(<RequestAccessForm />)
    await user.type(screen.getByLabelText(/company/i), 'Acme')
    await user.type(screen.getByLabelText(/work email/i), 'owner@acme.com')
    await user.click(screen.getByRole('button', { name: /send request/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/not accepted/i)
  })

  it('confirms with the token from the fragment and clears it from the address bar', async () => {
    window.history.replaceState(null, '', '/request-access/confirm#token=abc123')
    vi.mocked(confirmAccessRequestAction).mockResolvedValue({
      success: true,
      data: null,
      message: 'ok',
    })
    render(<RequestAccessConfirm />)
    await waitFor(() => expect(confirmAccessRequestAction).toHaveBeenCalledWith('abc123'))
    expect(window.location.hash).toBe('')
    expect(await screen.findByText(/confirmed and waits/i)).toBeInTheDocument()
  })

  it('a link without a token fails without calling the API', async () => {
    window.history.replaceState(null, '', '/request-access/confirm')
    render(<RequestAccessConfirm />)
    expect(await screen.findByText(/invalid or has expired/i)).toBeInTheDocument()
    expect(confirmAccessRequestAction).not.toHaveBeenCalled()
  })
})
