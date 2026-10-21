/**
 * The second sign-in step follows the user's language (owner rule: every UI
 * string through t()). It used to be English-only.
 */
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { I18nProvider } from '@/context/i18n-provider'

vi.mock('../actions/local-auth-actions', () => ({
  cancelMfaAction: vi.fn(),
  confirmMfaEnrollmentAction: vi.fn(),
  finishMfaEnrollmentAction: vi.fn(),
  startMfaEnrollmentAction: vi.fn(() => new Promise(() => {})),
  verifyMfaAction: vi.fn(),
}))

import { MfaStep } from './mfa-step'

describe('MfaStep i18n', () => {
  it('renders the verify step in Vietnamese', () => {
    render(
      <I18nProvider locale="vi">
        <MfaStep purpose="verify" onDone={vi.fn()} onCancel={vi.fn()} />
      </I18nProvider>
    )
    expect(screen.getByRole('heading', { name: 'Xác thực hai lớp' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Xác minh/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Dùng mã khôi phục' })).toBeInTheDocument()
  })

  it('renders the enrollment step in English by default', () => {
    render(<MfaStep purpose="enroll" onDone={vi.fn()} onCancel={vi.fn()} />)
    expect(
      screen.getByRole('heading', { name: 'Set up two-factor authentication' })
    ).toBeInTheDocument()
  })

  it('names the sign-in code field "Authentication code"', () => {
    render(<MfaStep purpose="verify" onDone={vi.fn()} onCancel={vi.fn()} />)
    const input = screen.getByLabelText('Authentication code')
    expect(input).toHaveAttribute('id', 'mfa-code')
    expect(input.tagName).toBe('INPUT')
  })

  it('names the recovery field "Recovery code" and follows the language', async () => {
    const { rerender } = render(<MfaStep purpose="verify" onDone={vi.fn()} onCancel={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'Use a recovery code instead' }))
    expect(screen.getByLabelText('Recovery code')).toBeInTheDocument()
    rerender(
      <I18nProvider locale="vi">
        <MfaStep purpose="verify" onDone={vi.fn()} onCancel={vi.fn()} />
      </I18nProvider>
    )
    expect(screen.getByLabelText('Mã xác thực')).toBeInTheDocument()
  })
})
