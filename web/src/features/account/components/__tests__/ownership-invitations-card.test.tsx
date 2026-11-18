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

  it('on its own page: one h1 in the entry card, teal accept without a leading icon', async () => {
    const own = { ...INV, organization_name: 'Example Org' }
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing([own]))
    vi.mocked(acceptOwnershipInvitation).mockResolvedValue({ organization_id: 't1' })
    const user = userEvent.setup()
    render(<OwnershipInvitationsCard surface="entry" />)
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(document.querySelector('[data-entry="card"]')).not.toBeNull()
    const accept = screen.getByRole('button', { name: /accept and become owner/i })
    expect(accept).toHaveAttribute('data-variant', 'signal')
    expect(accept.querySelector('svg')).toBeNull()
    await user.click(accept)
    await waitFor(() => expect(acceptOwnershipInvitation).toHaveBeenCalledWith('i1'))
  })

  it('fills no Accept when several invitations wait: one filled button per screen at most', () => {
    const two = [
      { ...INV, organization_name: 'Example Org' },
      { ...INV, id: 'i2', organization_id: 't2', organization_name: 'Example Two' },
    ]
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing(two))
    const { unmount } = render(<OwnershipInvitationsCard surface="entry" />)
    for (const b of screen.getAllByRole('button', { name: /accept and become owner/i }))
      expect(b).toHaveAttribute('data-variant', 'outline')
    // Each organization carries the shared organization avatar (initials).
    expect(
      [...document.querySelectorAll('[data-slot="org-avatar"]')].map((a) => a.textContent)
    ).toEqual(['EO', 'ET'])
    unmount()
    render(<OwnershipInvitationsCard />)
    for (const b of screen.getAllByRole('button', { name: /accept and become owner/i }))
      expect(b).toHaveAttribute('data-variant', 'outline')
  })

  it('on My account keeps the card without a page heading', () => {
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing([INV]))
    render(<OwnershipInvitationsCard />)
    expect(screen.queryByRole('heading', { level: 1 })).toBeNull()
    expect(document.querySelector('[data-entry="card"]')).toBeNull()
  })
})
