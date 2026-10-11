import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { bulkTypeToConfirm, ConfirmDialog } from '../confirm-dialog'

function renderDialog(props: Partial<React.ComponentProps<typeof ConfirmDialog>> = {}) {
  const handleConfirm = props.handleConfirm ?? vi.fn()
  const onOpenChange = props.onOpenChange ?? vi.fn()
  render(
    <ConfirmDialog
      open
      onOpenChange={onOpenChange}
      title="Delete widget?"
      desc="The widget is deleted."
      confirmText="Delete"
      destructive
      {...props}
      handleConfirm={handleConfirm}
    />
  )
  return { handleConfirm, onOpenChange }
}

describe('ConfirmDialog', () => {
  it('is an alert dialog that focuses Cancel, so Enter on open cancels', async () => {
    const { handleConfirm, onOpenChange } = renderDialog()
    expect(screen.getByRole('alertdialog')).toBeInTheDocument()
    const cancel = screen.getByRole('button', { name: 'Cancel' })
    await waitFor(() => expect(cancel).toHaveFocus())
    await userEvent.keyboard('{Enter}')
    expect(handleConfirm).not.toHaveBeenCalled()
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('runs the action only from the confirm button', async () => {
    const { handleConfirm } = renderDialog()
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(handleConfirm).toHaveBeenCalledTimes(1)
  })

  it('keeps the confirm button disabled until the exact text is typed', async () => {
    const { handleConfirm } = renderDialog({ typeToConfirm: 'prod-sensor' })
    const confirm = screen.getByRole('button', { name: 'Delete' })
    expect(confirm).toBeDisabled()
    const input = screen.getByLabelText(/Type\s*prod-sensor\s*to confirm/)
    await userEvent.type(input, 'prod-sens')
    expect(confirm).toBeDisabled()
    await userEvent.type(input, 'or{Enter}')
    // Enter in the field does not submit anything.
    expect(handleConfirm).not.toHaveBeenCalled()
    expect(confirm).toBeEnabled()
    await userEvent.click(confirm)
    expect(handleConfirm).toHaveBeenCalledTimes(1)
  })

  it('disables both buttons while a returned promise runs, so a second click does nothing', async () => {
    let finish: () => void = () => {}
    const handleConfirm = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve
        })
    )
    const { onOpenChange } = renderDialog({ handleConfirm })
    const confirm = screen.getByRole('button', { name: 'Delete' })
    await userEvent.click(confirm)
    expect(confirm).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled()
    await userEvent.click(confirm)
    await userEvent.keyboard('{Escape}')
    expect(handleConfirm).toHaveBeenCalledTimes(1)
    expect(onOpenChange).not.toHaveBeenCalledWith(false)
    finish()
    await waitFor(() => expect(confirm).toBeEnabled())
  })

  it('re-enables after a failed action so the user can retry or cancel', async () => {
    const handleConfirm = vi.fn(() => Promise.reject(new Error('boom')))
    renderDialog({ handleConfirm })
    const confirm = screen.getByRole('button', { name: 'Delete' })
    await userEvent.click(confirm)
    await waitFor(() => expect(confirm).toBeEnabled())
  })

  it('isLoading disables the action', () => {
    renderDialog({ isLoading: true })
    expect(screen.getByRole('button', { name: 'Delete' })).toBeDisabled()
  })
})

describe('bulkTypeToConfirm', () => {
  it('asks to type the count only for large batches', () => {
    expect(bulkTypeToConfirm(1)).toBeUndefined()
    expect(bulkTypeToConfirm(9)).toBeUndefined()
    expect(bulkTypeToConfirm(10)).toBe('10')
    expect(bulkTypeToConfirm(250)).toBe('250')
  })
})
