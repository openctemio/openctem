import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import { useOwnershipInvitations } from '../../api/use-ownership-invitations'
import { OwnershipInvitationBanner } from '../ownership-invitation-banner'

// The invitee learns about an organization created for them wherever they land
// after signing in, also on an installation that never emails them.

vi.mock('../../api/use-ownership-invitations', () => ({ useOwnershipInvitations: vi.fn() }))
const nav = vi.hoisted(() => ({ pathname: '/' }))
vi.mock('next/navigation', () => ({ usePathname: () => nav.pathname }))

const INV = {
  id: 'i1',
  organization_id: 't1',
  organization_name: 'Example Org',
  organization_slug: 'example-org',
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

describe('OwnershipInvitationBanner', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    nav.pathname = '/'
  })

  it('names the organization and links to the invitations page', () => {
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing([INV]))
    render(<OwnershipInvitationBanner />)
    expect(screen.getByTestId('ownership-invitation-banner')).toHaveTextContent('Example Org')
    expect(screen.getByRole('link', { name: 'Review invitation' })).toHaveAttribute(
      'href',
      '/ownership-invitations'
    )
  })

  it('counts several invitations', () => {
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing([INV, { ...INV, id: 'i2' }]))
    render(<OwnershipInvitationBanner />)
    expect(screen.getByTestId('ownership-invitation-banner')).toHaveTextContent('2 organizations')
  })

  it('is hidden with no invitation and on the invitations page itself', () => {
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing([]))
    const { rerender } = render(<OwnershipInvitationBanner />)
    expect(screen.queryByTestId('ownership-invitation-banner')).toBeNull()
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing([INV]))
    nav.pathname = '/ownership-invitations'
    rerender(<OwnershipInvitationBanner />)
    expect(screen.queryByTestId('ownership-invitation-banner')).toBeNull()
  })

  it('does not read the list before the session exists', () => {
    vi.mocked(useOwnershipInvitations).mockReturnValue(listing([]))
    render(<OwnershipInvitationBanner enabled={false} />)
    expect(useOwnershipInvitations).toHaveBeenCalledWith(false)
  })
})
