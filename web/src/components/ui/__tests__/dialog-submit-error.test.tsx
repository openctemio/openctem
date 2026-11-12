import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '../dialog'
import { DialogSubmitError } from '../dialog-submit-error'

function Frame({ message, requestId }: { message?: string | null; requestId?: string | null }) {
  return (
    <Dialog open>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add</DialogTitle>
          <DialogDescription>Add something</DialogDescription>
        </DialogHeader>
        <DialogForm onSubmit={(e) => e.preventDefault()}>
          <DialogBody>
            <p>fields</p>
          </DialogBody>
          <DialogSubmitError message={message} requestId={requestId} />
          <DialogFooter>
            <button type="submit">Save</button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

describe('DialogSubmitError', () => {
  it('is an alert placed between the scrolling body and the footer', () => {
    render(<Frame message="Could not save" />)
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('Could not save')
    expect(alert.closest('[data-slot="dialog-body"]')).toBeNull()
    const slot = alert.closest('[data-slot="dialog-submit-error"]')!
    expect(slot.nextElementSibling).toHaveAttribute('data-slot', 'dialog-footer')
  })

  it('shows the request id as a Reference line when present', () => {
    render(<Frame message="Refused" requestId="req-123" />)
    expect(screen.getByRole('alert')).toHaveTextContent('Reference: req-123')
  })

  it('has no Reference line without a request id', () => {
    render(<Frame message="Refused" />)
    expect(screen.getByRole('alert')).not.toHaveTextContent('Reference')
  })

  it('renders nothing without a message', () => {
    render(<Frame message={null} />)
    expect(screen.queryByRole('alert')).toBeNull()
  })
})
