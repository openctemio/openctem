import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import { en, vi as vi_ } from '@/lib/i18n/dictionaries'
import { PUBLIC_ROUTES } from '@/lib/middleware/config'
import { verifyEmailAction } from '../actions/local-auth-actions'
import { VerifyEmail } from './verify-email'

vi.mock('../actions/local-auth-actions', () => ({
  verifyEmailAction: vi.fn(),
}))

describe('verify email', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState(null, '', '/verify-email')
  })

  it('has en and vi text and opens without a session', () => {
    const keys = Object.keys(en).filter((k) => k.startsWith('auth.verifyEmail.'))
    expect(keys).toHaveLength(3)
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
})
