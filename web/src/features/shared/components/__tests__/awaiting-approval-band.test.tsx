import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { AwaitingApprovalBand, AwaitingApprovalRequest } from '../awaiting-approval-band'

function band(props: Partial<React.ComponentProps<typeof AwaitingApprovalRequest>> = {}) {
  return render(
    <AwaitingApprovalBand>
      <AwaitingApprovalRequest
        title="Awaiting approval: scope change"
        requestedBy="Requested by An Nguyen 2 hours ago"
        {...props}
      />
    </AwaitingApprovalBand>
  )
}

describe('AwaitingApprovalBand', () => {
  it('is a named region that says what is waiting and who asked', () => {
    band({ reason: 'new subsidiary' })
    expect(screen.getByRole('region', { name: 'Waiting on an approval' })).toBeInTheDocument()
    expect(screen.getByText('Awaiting approval: scope change')).toBeInTheDocument()
    expect(screen.getByText('Requested by An Nguyen 2 hours ago')).toBeInTheDocument()
    expect(screen.getByText(/Reason:\s*new subsidiary/)).toBeInTheDocument()
  })

  it('offers no Cancel unless the caller says the viewer may cancel', () => {
    band()
    expect(screen.queryByRole('button', { name: 'Cancel request' })).toBeNull()
  })

  it('asks before cancelling, then runs the cancel once', async () => {
    const onCancel = vi.fn().mockResolvedValue(undefined)
    band({ onCancel })
    fireEvent.click(screen.getByTestId('awaiting-approval-cancel'))
    expect(onCancel).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('Cancel this approval request?')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel request' }))
    await waitFor(() => expect(onCancel).toHaveBeenCalledTimes(1))
  })

  it('"Keep request" leaves the request alone', async () => {
    const onCancel = vi.fn()
    band({ onCancel })
    fireEvent.click(screen.getByTestId('awaiting-approval-cancel'))
    const dialog = await screen.findByRole('alertdialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Keep request' }))
    expect(onCancel).not.toHaveBeenCalled()
  })

  it('uses the confirmation copy of the caller when the generic wording does not fit', async () => {
    band({
      onCancel: vi.fn(),
      cancelDialog: { title: 'Withdraw the exception?', description: 'The finding stays open.' },
    })
    fireEvent.click(screen.getByTestId('awaiting-approval-cancel'))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('Withdraw the exception?')).toBeInTheDocument()
    expect(within(dialog).getByText('The finding stays open.')).toBeInTheDocument()
  })

  it('disables Cancel while it runs and shows a failure beside the buttons', () => {
    band({ onCancel: vi.fn(), cancelBusy: true, error: 'Failed to cancel request' })
    expect(screen.getByTestId('awaiting-approval-cancel')).toBeDisabled()
    expect(screen.getByRole('alert')).toHaveTextContent('Failed to cancel request')
  })

  it("renders the approver's buttons and the caller's details and dialogs", () => {
    render(
      <AwaitingApprovalBand after={<div>approver dialogs</div>}>
        <AwaitingApprovalRequest
          title="t"
          requestedBy="r"
          details={<span>changed since: kev</span>}
          actions={<button type="button">Approve</button>}
        />
      </AwaitingApprovalBand>
    )
    expect(screen.getByText('changed since: kev')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Approve' })).toBeInTheDocument()
    expect(screen.getByText('approver dialogs')).toBeInTheDocument()
  })
})
