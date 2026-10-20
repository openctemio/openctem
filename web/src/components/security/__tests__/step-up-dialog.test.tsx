import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { StepUpDialog, type StepUpDialogProps } from '../step-up-dialog'

function renderDialog(props: Partial<StepUpDialogProps> = {}) {
  const onSubmit = props.onSubmit ?? vi.fn().mockResolvedValue(undefined)
  const onOpenChange = props.onOpenChange ?? vi.fn()
  render(<StepUpDialog open onOpenChange={onOpenChange} onSubmit={onSubmit} {...props} />)
  return { onSubmit, onOpenChange }
}

describe('StepUpDialog', () => {
  it('submits on its own once the code is complete', async () => {
    const user = userEvent.setup()
    const { onSubmit } = renderDialog()
    expect(screen.getByRole('dialog', { name: 'Confirm it is you' })).toBeInTheDocument()
    await user.type(
      screen.getByRole('textbox', { name: 'Code from your authenticator app' }),
      '123456'
    )
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith({ kind: 'totp', code: '123456' }))
    expect(onSubmit).toHaveBeenCalledTimes(1)
  })

  it('waits for the other fields before submitting, then submits from the button', async () => {
    const user = userEvent.setup()
    const { onSubmit } = renderDialog({ ready: false, children: <p>reason</p> })
    await user.type(screen.getByRole('textbox'), '123456')
    expect(onSubmit).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeDisabled()
  })

  it('autoSubmit off: the button sends the code', async () => {
    const user = userEvent.setup()
    const { onSubmit } = renderDialog({ autoSubmit: false, submitLabel: 'Approve' })
    await user.type(screen.getByRole('textbox'), '123456')
    expect(onSubmit).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    expect(onSubmit).toHaveBeenCalledWith({ kind: 'totp', code: '123456' })
  })

  it('a refused code is shown, cleared and the field refocused', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn().mockRejectedValue({ statusCode: 401, message: 'Invalid code' })
    renderDialog({ onSubmit })
    const input = screen.getByRole('textbox')
    await user.type(input, '000000')
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid code')
    expect(input).toHaveValue('')
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveFocus()
  })

  it('too many attempts gets the rate-limit message', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn().mockRejectedValue({ statusCode: 429, message: 'slow down' })
    renderDialog({ onSubmit })
    await user.type(screen.getByRole('textbox'), '000000')
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Too many attempts. Wait a minute and try again.'
    )
  })

  it('offers a recovery code and sends it as recovery', async () => {
    const user = userEvent.setup()
    const { onSubmit } = renderDialog({ recovery: { length: 10, groups: [5, 5] } })
    await user.click(screen.getByRole('button', { name: 'Use a recovery code instead' }))
    const input = screen.getByRole('textbox', { name: 'Recovery code' })
    await user.type(input, 'abcde-fghjk')
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith({ kind: 'recovery', code: 'abcdefghjk' })
    )
    await user.click(screen.getByRole('button', { name: 'Use your authenticator app instead' }))
    expect(
      screen.getByRole('textbox', { name: 'Code from your authenticator app' })
    ).toBeInTheDocument()
  })

  it('offers a preferred passkey first, with the code as a fallback', async () => {
    const user = userEvent.setup()
    const onUse = vi.fn().mockResolvedValue(undefined)
    const { onSubmit } = renderDialog({ passkey: { onUse, preferred: true, supported: true } })
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Use security key or passkey' }))
    expect(onUse).toHaveBeenCalledTimes(1)

    await user.click(
      screen.getByRole('button', { name: 'Use a code from your authenticator app instead' })
    )
    await user.type(screen.getByRole('textbox'), '123456')
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith({ kind: 'totp', code: '123456' }))
  })

  it('a required key has no code fallback', () => {
    renderDialog({ passkey: { onUse: vi.fn(), required: true, supported: true } })
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Use a code from your authenticator app instead' })
    ).not.toBeInTheDocument()
    expect(screen.getByText(/security key is required/i)).toBeInTheDocument()
  })

  it('password factor asks for the password', async () => {
    const user = userEvent.setup()
    const { onSubmit } = renderDialog({ factor: 'password' })
    await user.type(screen.getByLabelText('Password'), 'secret')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(onSubmit).toHaveBeenCalledWith({ kind: 'password', password: 'secret' })
  })

  it('shows a problem from outside the dialog on the code field', () => {
    renderDialog({ problem: 'The code was refused.' })
    expect(screen.getByRole('alert')).toHaveTextContent('The code was refused.')
  })

  it('cancel closes', async () => {
    const user = userEvent.setup()
    const { onOpenChange } = renderDialog()
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })
})
