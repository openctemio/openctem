/**
 * The two-factor page names the step the API asked for. A person whose 2FA is
 * already on is only asked for a code, so the page must not say "Set up" and
 * then show no QR code (UI audit 2026-11-27, /two-factor-setup).
 */
import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

const start = vi.fn()
vi.mock('../actions/local-auth-actions', () => ({
  cancelMfaAction: vi.fn(),
  confirmMfaEnrollmentAction: vi.fn(),
  finishMfaEnrollmentAction: vi.fn(),
  startMfaEnrollmentAction: vi.fn(() => new Promise(() => {})),
  verifyMfaAction: vi.fn(),
  selectTenantAction: vi.fn(),
  localLogoutAction: vi.fn(() => Promise.resolve()),
  startSessionMfaAction: () => start(),
}))
vi.mock('@/lib/session-navigation', () => ({ navigateAfterSessionChange: vi.fn() }))

import { TwoFactorSetup } from './two-factor-setup'

describe('TwoFactorSetup heading', () => {
  it('says "Confirm" with one heading when 2FA is already on', async () => {
    start.mockResolvedValue({ success: true, purpose: 'verify' })
    render(<TwoFactorSetup />)
    expect(
      await screen.findByRole('heading', { name: 'Confirm two-factor authentication' })
    ).toBeInTheDocument()
    expect(screen.queryByText('Set up two-factor authentication')).not.toBeInTheDocument()
    // The verify step does not add a second heading under the page's own.
    expect(screen.getAllByRole('heading')).toHaveLength(1)
    expect(screen.getByLabelText('Authentication code')).toBeInTheDocument()
  })

  it('says "Set up" when the person has no second factor yet', async () => {
    start.mockResolvedValue({ success: true, purpose: 'enroll' })
    render(<TwoFactorSetup />)
    expect(
      await screen.findByRole('heading', { name: 'Set up two-factor authentication' })
    ).toBeInTheDocument()
  })
})
