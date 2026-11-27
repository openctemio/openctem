import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { toast } from 'sonner'

import { useEmailUnavailable } from '@/features/auth/api/use-auth-providers'
import { forgotPasswordAction } from '@/features/auth/actions/local-auth-actions'
import ForgotPasswordPage from './page'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

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

  it('shows a refused request once, as a banner on the page', async () => {
    vi.mocked(useEmailUnavailable).mockReturnValue(false)
    vi.mocked(forgotPasswordAction).mockResolvedValue({ success: false, error: 'refused' })
    render(<ForgotPasswordPage />)
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'a@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/something went wrong/i)
    expect(vi.mocked(toast.error)).not.toHaveBeenCalled()
  })
})
