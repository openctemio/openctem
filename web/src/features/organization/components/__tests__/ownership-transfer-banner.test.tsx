import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

const accept = vi.fn()
const decline = vi.fn()
const cancel = vi.fn()
vi.mock('../../api/use-ownership-transfer', () => ({
  acceptOwnershipTransfer: () => accept(),
  declineOwnershipTransfer: () => decline(),
  cancelOwnershipTransfer: () => cancel(),
}))
vi.mock('@/lib/api/client', () => ({ refreshSession: vi.fn() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { OwnershipTransferBanner } from '../ownership-transfer-banner'
import type { OwnershipTransfer } from '../../api/use-ownership-transfer'

const transfer: OwnershipTransfer = {
  id: 't1',
  status: 'pending',
  from_user_id: 'u-owner',
  from_name: 'Olivia',
  to_user_id: 'u-new',
  to_name: 'Pat',
  previous_owner_role: 'admin',
  make_internal: false,
  created_at: '2026-10-15T00:00:00Z',
  expires_at: '2026-10-18T00:00:00Z',
  viewer: 'new_owner',
}

describe('OwnershipTransferBanner', () => {
  beforeEach(() => {
    accept.mockReset().mockResolvedValue({})
    decline.mockReset().mockResolvedValue(undefined)
    cancel.mockReset().mockResolvedValue(undefined)
  })

  it('renders nothing without a transfer', () => {
    const { container } = render(<OwnershipTransferBanner transfer={null} onChanged={vi.fn()} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('lets the member asked accept after confirming', async () => {
    const onChanged = vi.fn()
    render(
      <OwnershipTransferBanner
        transfer={transfer}
        onChanged={onChanged}
        reloadAfterAccept={false}
      />
    )
    expect(screen.getByText('Olivia asked you to become the owner')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Accept ownership' }))
    const buttons = await screen.findAllByRole('button', { name: 'Accept ownership' })
    fireEvent.click(buttons[buttons.length - 1])
    await waitFor(() => expect(accept).toHaveBeenCalled())
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
  })

  it('lets the member asked decline', async () => {
    render(<OwnershipTransferBanner transfer={transfer} onChanged={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Decline' }))
    const buttons = await screen.findAllByRole('button', { name: 'Decline' })
    fireEvent.click(buttons[buttons.length - 1])
    await waitFor(() => expect(decline).toHaveBeenCalled())
    expect(accept).not.toHaveBeenCalled()
  })

  it('shows the owner the waiting state with a cancel action only', async () => {
    render(
      <OwnershipTransferBanner transfer={{ ...transfer, viewer: 'owner' }} onChanged={vi.fn()} />
    )
    expect(screen.getByText('Waiting for Pat to accept ownership')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Accept ownership' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel transfer' }))
    const buttons = await screen.findAllByRole('button', { name: 'Cancel transfer' })
    fireEvent.click(buttons[buttons.length - 1])
    await waitFor(() => expect(cancel).toHaveBeenCalled())
  })
})
