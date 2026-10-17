import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiClientError } from '@/lib/api/error-handler'
import type { MemberWithUser } from '../../types/member.types'

// Radix Checkbox measures itself; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const { start } = vi.hoisted(() => ({ start: vi.fn() }))
vi.mock('../../api/use-ownership-transfer', () => ({ startOwnershipTransfer: start }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { TransferOwnershipDialog } from '../transfer-ownership-dialog'

const member: MemberWithUser = {
  id: 'm1',
  user_id: 'u1',
  role: 'member',
  joined_at: '2026-01-01T00:00:00Z',
  email: 'pat@example.com',
  name: 'Pat',
  status: 'active',
  mfa_status: 'enabled',
  kind: 'internal',
}

describe('TransferOwnershipDialog', () => {
  beforeEach(() => {
    start.mockReset()
  })

  it('asks with the previous owner becoming an administrator by default', async () => {
    start.mockResolvedValue({})
    const onOpenChange = vi.fn()
    render(<TransferOwnershipDialog member={member} onOpenChange={onOpenChange} />)
    fireEvent.click(screen.getByRole('button', { name: 'Ask to transfer' }))
    await waitFor(() =>
      expect(start).toHaveBeenCalledWith({
        member_id: 'm1',
        previous_owner_role: 'admin',
        confirm_internal: undefined,
      })
    )
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('cannot ask a member without two-factor authentication', () => {
    render(
      <TransferOwnershipDialog
        member={{ ...member, mfa_status: 'disabled' }}
        onOpenChange={vi.fn()}
      />
    )
    expect(screen.getByRole('button', { name: 'Ask to transfer' })).toBeDisabled()
    expect(
      screen.getByText('They must turn on two-factor authentication first.')
    ).toBeInTheDocument()
  })

  it('needs the confirmation for an outsider, then sends it', async () => {
    start.mockResolvedValue({})
    render(
      <TransferOwnershipDialog member={{ ...member, kind: 'external' }} onOpenChange={vi.fn()} />
    )
    const submit = screen.getByRole('button', { name: 'Ask to transfer' })
    expect(submit).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(submit)
    await waitFor(() =>
      expect(start).toHaveBeenCalledWith(expect.objectContaining({ confirm_internal: true }))
    )
  })

  it('shows a translated API refusal', async () => {
    start.mockRejectedValue(new ApiClientError('x', 'OWNERSHIP_TRANSFER_PENDING', 409))
    render(<TransferOwnershipDialog member={member} onOpenChange={vi.fn()} />)
    await userEvent.setup().click(screen.getByRole('button', { name: 'Ask to transfer' }))
    expect(
      await screen.findByText('A transfer is already waiting for an answer. Cancel it first.')
    ).toBeInTheDocument()
  })
})
