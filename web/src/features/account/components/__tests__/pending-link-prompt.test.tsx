import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const getPendingLinkAction = vi.fn()
const confirmPendingLinkAction = vi.fn()
const dismissPendingLinkAction = vi.fn()
vi.mock('@/features/auth/actions/social-auth-actions', () => ({
  getPendingLinkAction: () => getPendingLinkAction(),
  confirmPendingLinkAction: () => confirmPendingLinkAction(),
  dismissPendingLinkAction: () => dismissPendingLinkAction(),
}))
const requestStepUp = vi.fn()
vi.mock('@/lib/api/step-up', () => ({
  STEP_UP_REQUIRED_CODE: 'STEP_UP_REQUIRED',
  requestStepUp: () => requestStepUp(),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

import { PendingLinkPrompt } from '../pending-link-prompt'

describe('PendingLinkPrompt', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPendingLinkAction.mockResolvedValue({ provider: 'google', email: 'p@gmail.com' })
    dismissPendingLinkAction.mockResolvedValue(undefined)
  })

  it('shows nothing without a pending link of this account', async () => {
    getPendingLinkAction.mockResolvedValue(null)
    render(<PendingLinkPrompt />)
    await waitFor(() => expect(getPendingLinkAction).toHaveBeenCalled())
    expect(screen.queryByRole('alertdialog')).toBeNull()
  })

  it('asks before linking, naming the provider account', async () => {
    confirmPendingLinkAction.mockResolvedValue({ success: true })
    render(<PendingLinkPrompt />)
    expect(await screen.findByText('Link Google to your account?')).toBeInTheDocument()
    expect(screen.getByText(/p@gmail\.com/)).toBeInTheDocument()
    expect(confirmPendingLinkAction).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Link Google' }))
    await waitFor(() => expect(confirmPendingLinkAction).toHaveBeenCalledTimes(1))
    expect(toast.success).toHaveBeenCalled()
  })

  it('asks for a step-up when the sign-in is too old, then retries once', async () => {
    confirmPendingLinkAction
      .mockResolvedValueOnce({ success: false, code: 'STEP_UP_REQUIRED' })
      .mockResolvedValueOnce({ success: true })
    requestStepUp.mockResolvedValue(true)
    render(<PendingLinkPrompt />)
    await userEvent.click(await screen.findByRole('button', { name: 'Link Google' }))
    await waitFor(() => expect(confirmPendingLinkAction).toHaveBeenCalledTimes(2))
    expect(requestStepUp).toHaveBeenCalledTimes(1)
  })

  it('"Not now" drops the pending link', async () => {
    render(<PendingLinkPrompt />)
    await userEvent.click(await screen.findByRole('button', { name: 'Not now' }))
    await waitFor(() => expect(dismissPendingLinkAction).toHaveBeenCalled())
    expect(confirmPendingLinkAction).not.toHaveBeenCalled()
  })
})
