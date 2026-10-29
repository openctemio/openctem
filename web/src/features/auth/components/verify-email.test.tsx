import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { en, vi as vi_ } from '@/lib/i18n/dictionaries'
import { PUBLIC_ROUTES } from '@/lib/middleware/config'
import { post } from '@/lib/api/client'
import { useEmailUnavailable } from '../api/use-auth-providers'
import { verifyEmailAction } from '../actions/local-auth-actions'
import { VerifyEmail } from './verify-email'

vi.mock('../actions/local-auth-actions', () => ({
  verifyEmailAction: vi.fn(),
}))

vi.mock('@/lib/api/client', () => ({ post: vi.fn() }))
vi.mock('../api/use-auth-providers', () => ({ useEmailUnavailable: vi.fn(() => false) }))

describe('verify email', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState(null, '', '/verify-email')
  })

  it('has en and vi text and opens without a session', () => {
    const keys = Object.keys(en).filter((k) => k.startsWith('auth.verifyEmail.'))
    expect(keys).toHaveLength(8)
    for (const key of keys) expect((vi_ as Record<string, string>)[key], key).toBeTruthy()
    expect(PUBLIC_ROUTES).toContain('/verify-email')
  })

  it('posts the token from the fragment and removes it from the address bar', async () => {
    vi.mocked(verifyEmailAction).mockResolvedValue({ success: true, data: null, message: 'ok' })
    window.history.replaceState(null, '', '/verify-email#token=tok-1')
    render(<VerifyEmail />)
    expect(await screen.findByText(/your email address is verified/i)).toBeInTheDocument()
    expect(verifyEmailAction).toHaveBeenCalledWith('tok-1')
    expect(window.location.hash).toBe('')
  })

  it('says the link is invalid when the API refuses it', async () => {
    vi.mocked(verifyEmailAction).mockResolvedValue({ success: false, error: 'expired' })
    window.history.replaceState(null, '', '/verify-email#token=old')
    render(<VerifyEmail />)
    expect(await screen.findByText(/invalid or has expired/i)).toBeInTheDocument()
  })

  it('does not call the API without a token', async () => {
    render(<VerifyEmail />)
    expect(await screen.findByText(/invalid or has expired/i)).toBeInTheDocument()
    expect(verifyEmailAction).not.toHaveBeenCalled()
  })

  describe('a failed link offers a new one', () => {
    beforeEach(() => {
      vi.mocked(verifyEmailAction).mockResolvedValue({ success: false, error: 'expired' })
      window.history.replaceState(null, '', '/verify-email#token=old')
    })

    it('posts the typed address and answers the same whatever the address is', async () => {
      vi.mocked(post).mockResolvedValue({})
      render(<VerifyEmail />)
      await screen.findByText(/invalid or has expired/i)
      await userEvent.type(screen.getByLabelText(/email address/i), 'person@corp.test')
      await userEvent.click(screen.getByRole('button', { name: /send a new verification link/i }))
      await waitFor(() =>
        expect(post).toHaveBeenCalledWith('/api/v1/auth/resend-verification', {
          email: 'person@corp.test',
        })
      )
      expect(await screen.findByText(/if this address has an account/i)).toBeInTheDocument()
    })

    it('tells the person to ask an administrator when the server cannot send email', async () => {
      vi.mocked(useEmailUnavailable).mockReturnValue(true)
      render(<VerifyEmail />)
      expect(
        await screen.findByText(/ask your administrator to verify your address/i)
      ).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /send a new verification link/i })).toBeNull()
      vi.mocked(useEmailUnavailable).mockReturnValue(false)
    })
  })
})
