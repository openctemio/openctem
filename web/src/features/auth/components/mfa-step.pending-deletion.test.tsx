/**
 * An owner whose sign-in uses two-factor, and whose organization is waiting
 * for deletion, must reach the cancel-deletion prompt: the login result after
 * the second factor is success:false with pendingDeletion set.
 */
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const actions = vi.hoisted(() => ({
  cancelMfaAction: vi.fn(),
  confirmMfaEnrollmentAction: vi.fn(),
  finishMfaEnrollmentAction: vi.fn(),
  startMfaEnrollmentAction: vi.fn(),
  verifyMfaAction: vi.fn(),
}))
vi.mock('../actions/local-auth-actions', () => actions)

import { MfaStep } from './mfa-step'

const org = { id: 't1', name: 'Acme', slug: 'acme', role: 'owner', deletion_due_at: '2026-12-01' }
const pending = { success: false, error: 'suspended', pendingDeletion: [org] }

beforeEach(() => vi.clearAllMocks())

describe('MfaStep verify', () => {
  function submitCode() {
    fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /Verify/ }))
  }

  it('hands a pending-deletion result to onDone', async () => {
    actions.verifyMfaAction.mockResolvedValue(pending)
    const onDone = vi.fn()
    render(<MfaStep purpose="verify" onDone={onDone} onCancel={vi.fn()} />)
    submitCode()
    await waitFor(() => expect(onDone).toHaveBeenCalledWith(pending))
  })

  it('hands a normal success to onDone', async () => {
    const ok = { success: true }
    actions.verifyMfaAction.mockResolvedValue(ok)
    const onDone = vi.fn()
    render(<MfaStep purpose="verify" onDone={onDone} onCancel={vi.fn()} />)
    submitCode()
    await waitFor(() => expect(onDone).toHaveBeenCalledWith(ok))
  })

  it('shows a wrong-code error and does not continue', async () => {
    actions.verifyMfaAction.mockResolvedValue({ success: false, error: 'Invalid code' })
    const onDone = vi.fn()
    render(<MfaStep purpose="verify" onDone={onDone} onCancel={vi.fn()} />)
    submitCode()
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid code')
    expect(onDone).not.toHaveBeenCalled()
  })
})

describe('MfaStep enroll', () => {
  async function reachCodesStep() {
    actions.confirmMfaEnrollmentAction.mockResolvedValue({ success: true, recoveryCodes: ['a-b'] })
    await waitFor(() => expect(screen.getByLabelText('Authentication code')).not.toBeDisabled())
    fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /Turn on and continue/ }))
    fireEvent.click(await screen.findByLabelText('I have saved my recovery codes'))
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
  }

  function mountEnroll(onDone = vi.fn(), onCancel = vi.fn()) {
    actions.startMfaEnrollmentAction.mockResolvedValue({
      success: true,
      secret: 'ABCDEF',
      otpauthUri: 'otpauth://totp/x?secret=ABCDEF',
    })
    render(<MfaStep purpose="enroll" onDone={onDone} onCancel={onCancel} />)
    return { onDone, onCancel }
  }

  it('hands a pending-deletion result to onDone after setup', async () => {
    actions.finishMfaEnrollmentAction.mockResolvedValue(pending)
    const { onDone, onCancel } = mountEnroll()
    await reachCodesStep()
    await waitFor(() => expect(onDone).toHaveBeenCalledWith(pending))
    expect(onCancel).not.toHaveBeenCalled()
  })

  it('hands a normal success to onDone after setup', async () => {
    const ok = { success: true }
    actions.finishMfaEnrollmentAction.mockResolvedValue(ok)
    const { onDone } = mountEnroll()
    await reachCodesStep()
    await waitFor(() => expect(onDone).toHaveBeenCalledWith(ok))
  })

  it('goes back to sign-in with the error when finishing fails', async () => {
    actions.finishMfaEnrollmentAction.mockResolvedValue({ success: false, error: 'Expired' })
    const { onDone, onCancel } = mountEnroll()
    await reachCodesStep()
    await waitFor(() => expect(onCancel).toHaveBeenCalledWith('Expired'))
    expect(onDone).not.toHaveBeenCalled()
  })
})
