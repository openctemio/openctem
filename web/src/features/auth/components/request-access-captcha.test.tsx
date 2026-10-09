import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { submitAccessRequestAction } from '../actions/local-auth-actions'
import { RequestAccessForm } from './request-access-form'

vi.mock('../api/use-auth-providers', () => ({
  useAuthProviders: () => ({ data: { request_access: true, captcha_site_key: 'site-key-1' } }),
}))
vi.mock('../actions/local-auth-actions', () => ({
  submitAccessRequestAction: vi.fn(),
  confirmAccessRequestAction: vi.fn(),
}))

type RenderOpts = { sitekey: string; callback: (t: string) => void; 'expired-callback': () => void }

describe('request access with a CAPTCHA', () => {
  let rendered: RenderOpts | null
  beforeEach(() => {
    vi.clearAllMocks()
    rendered = null
    window.turnstile = {
      render: (_el, opts) => {
        rendered = opts as RenderOpts
        return 'w1'
      },
      remove: vi.fn(),
    }
  })
  afterEach(() => {
    delete window.turnstile
  })

  async function fill() {
    const user = userEvent.setup()
    render(<RequestAccessForm />)
    await user.type(screen.getByLabelText(/company/i), 'Acme')
    await user.type(screen.getByLabelText(/work email/i), 'owner@acme.com')
    return user
  }

  it('renders the widget with the site key and waits for a token', async () => {
    await fill()
    await waitFor(() => expect(rendered?.sitekey).toBe('site-key-1'))
    expect(screen.getByRole('button', { name: /send request/i })).toBeDisabled()
  })

  it('sends the token with the request', async () => {
    vi.mocked(submitAccessRequestAction).mockResolvedValue({
      success: true,
      data: null,
      message: 'x',
    })
    const user = await fill()
    await waitFor(() => expect(rendered).not.toBeNull())
    rendered!.callback('tok-123')
    const send = screen.getByRole('button', { name: /send request/i })
    await waitFor(() => expect(send).toBeEnabled())
    await user.click(send)
    await waitFor(() =>
      expect(submitAccessRequestAction).toHaveBeenCalledWith({
        company: 'Acme',
        email: 'owner@acme.com',
        note: '',
        captcha_token: 'tok-123',
      })
    )
  })

  it('an expired token disables sending again', async () => {
    await fill()
    await waitFor(() => expect(rendered).not.toBeNull())
    rendered!.callback('tok-123')
    const send = screen.getByRole('button', { name: /send request/i })
    await waitFor(() => expect(send).toBeEnabled())
    rendered!['expired-callback']()
    await waitFor(() => expect(send).toBeDisabled())
  })
})
