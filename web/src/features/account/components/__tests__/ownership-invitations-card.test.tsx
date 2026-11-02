import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  acceptOwnershipInvitation,
  declineOwnershipInvitation,
  useOwnershipInvitations,
} from '../../api/use-ownership-invitations'
import { OwnershipInvitationsCard } from '../ownership-invitations-card'

vi.mock('../../api/use-ownership-invitations', () => ({
  useOwnershipInvitations: vi.fn(),
  acceptOwnershipInvitation: vi.fn(),
  declineOwnershipInvitation: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
const tenantCtx = vi.hoisted(() => ({
  tenants: [] as { id: string }[],
  refreshTenants: vi.fn(),
  switchTeam: vi.fn(),
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => tenantCtx }))

const INV = {
  id: 'i1',
  organization_id: 't1',
  organization_name: 'VNDS',
  organization_slug: 'vnds',
  invited_at: '2026-11-01T00:00:00Z',
  expires_at: '2099-01-01T00:00:00Z',
}

function listing(invitations: (typeof INV)[]) {
  return {
    invitations,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  } as unknown as ReturnType<typeof useOwnershipInvitations>
}

describe('OwnershipInvitationsCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('renders nothing on My account when no invitation waits', () => {
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing([]))
    const { container } = render(<OwnershipInvitationsCard hideWhenEmpty />)
    expect(container).toBeEmptyDOMElement()
  })

  it('accepts an invitation', async () => {
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing([INV]))
    vi.mocked(acceptOwnershipInvitation).mockResolvedValue({ organization_id: 't1' })
    const user = userEvent.setup()
    render(<OwnershipInvitationsCard />)
    expect(screen.getByText('VNDS')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /accept and become owner/i }))
    await waitFor(() => expect(acceptOwnershipInvitation).toHaveBeenCalledWith('i1'))
    await waitFor(() => expect(tenantCtx.refreshTenants).toHaveBeenCalled())
  })

  it('declines after confirmation', async () => {
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing([INV]))
    vi.mocked(declineOwnershipInvitation).mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<OwnershipInvitationsCard />)
    await user.click(screen.getByRole('button', { name: /^decline$/i }))
    const buttons = await screen.findAllByRole('button', { name: /^decline$/i })
    await user.click(buttons[buttons.length - 1])
    await waitFor(() => expect(declineOwnershipInvitation).toHaveBeenCalledWith('i1'))
  })
})
