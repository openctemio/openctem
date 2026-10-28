import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { useEmailUnavailable } from '@/features/auth/api/use-auth-providers'
import ForgotPasswordPage from './page'

vi.mock('@/features/auth/api/use-auth-providers', () => ({
  useEmailUnavailable: vi.fn(() => false),
  usePasswordPolicy: () => undefined,
}))
vi.mock('@/features/auth/actions/local-auth-actions', () => ({ forgotPasswordAction: vi.fn() }))

describe('forgot password', () => {
  it('asks for an email address when the server can send email', () => {
    render(<ForgotPasswordPage />)
    expect(screen.getByRole('button', { name: /send reset link/i })).toBeInTheDocument()
  })

  it('does not promise an email when the server cannot send one', () => {
    vi.mocked(useEmailUnavailable).mockReturnValue(true)
    render(<ForgotPasswordPage />)
    expect(screen.getByText(/ask your administrator for a reset link/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /send reset link/i })).toBeNull()
    expect(screen.queryByLabelText(/email/i)).toBeNull()
  })
})
