import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
)

const getPendingLinkAction = vi.fn()
const confirmPendingLinkAction = vi.fn()
const dismissPendingLinkAction = vi.fn()
vi.mock('@/features/auth/actions/social-auth-actions', () => ({
  getPendingLinkAction: () => getPendingLinkAction(),
  confirmPendingLinkAction: (proof: unknown) => confirmPendingLinkAction(proof),
  dismissPendingLinkAction: () => dismissPendingLinkAction(),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

import { PendingLinkPrompt } from '../pending-link-prompt'

describe('PendingLinkPrompt', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPendingLinkAction.mockResolvedValue({
      provider: 'google',
      email: 'p@gmail.com',
      proof: 'totp',
    })
    dismissPendingLinkAction.mockResolvedValue(undefined)
  })

  it('shows nothing without a pending link of this account', async () => {
    getPendingLinkAction.mockResolvedValue(null)
    render(<PendingLinkPrompt />)
    await waitFor(() => expect(getPendingLinkAction).toHaveBeenCalled())
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('asks for the authenticator code before linking, naming the provider account', async () => {
    confirmPendingLinkAction.mockResolvedValue({ success: true })
    const user = userEvent.setup()
    render(<PendingLinkPrompt />)
    expect(await screen.findByText('Link Google to your account?')).toBeInTheDocument()
    expect(screen.getByText(/p@gmail\.com/)).toBeInTheDocument()
    expect(screen.getByText(/Enter the code from your authenticator app/)).toBeInTheDocument()
    expect(confirmPendingLinkAction).not.toHaveBeenCalled()
    await user.type(screen.getByRole('textbox'), '123456')
    await waitFor(() => expect(confirmPendingLinkAction).toHaveBeenCalledWith({ totp: '123456' }))
    expect(toast.success).toHaveBeenCalled()
  })

  it('a password account confirms with its password', async () => {
    getPendingLinkAction.mockResolvedValue({
      provider: 'google',
      email: 'p@gmail.com',
      proof: 'password',
    })
    confirmPendingLinkAction.mockResolvedValue({ success: true })
    const user = userEvent.setup()
    render(<PendingLinkPrompt />)
    await user.type(await screen.findByLabelText('Password'), 'pw-1')
    await user.click(screen.getByRole('button', { name: 'Link Google' }))
    expect(confirmPendingLinkAction).toHaveBeenCalledWith({ password: 'pw-1' })
  })

  it('a wrong code is shown in place and the person can try again', async () => {
    confirmPendingLinkAction
      .mockResolvedValueOnce({ success: false, code: 'LINK_PROOF_FAILED' })
      .mockResolvedValueOnce({ success: true })
    const user = userEvent.setup()
    render(<PendingLinkPrompt />)
    await user.type(await screen.findByRole('textbox'), '000000')
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The code or password is not correct.'
    )
    expect(toast.error).not.toHaveBeenCalled()
    await user.type(screen.getByRole('textbox'), '123456')
    await waitFor(() => expect(confirmPendingLinkAction).toHaveBeenCalledTimes(2))
    expect(toast.success).toHaveBeenCalled()
  })

  it('an account without a code or password is told to turn on two-factor first', async () => {
    getPendingLinkAction.mockResolvedValue({ provider: 'google', email: 'p@gmail.com', proof: '' })
    const user = userEvent.setup()
    render(<PendingLinkPrompt />)
    expect(await screen.findByText(/Turn on two-factor authentication/)).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Not now' }))
    await waitFor(() => expect(dismissPendingLinkAction).toHaveBeenCalled())
    expect(confirmPendingLinkAction).not.toHaveBeenCalled()
  })

  it('closing drops the pending link', async () => {
    const user = userEvent.setup()
    render(<PendingLinkPrompt />)
    await screen.findByText('Link Google to your account?')
    await user.keyboard('{Escape}')
    await waitFor(() => expect(dismissPendingLinkAction).toHaveBeenCalled())
    expect(confirmPendingLinkAction).not.toHaveBeenCalled()
  })
})
