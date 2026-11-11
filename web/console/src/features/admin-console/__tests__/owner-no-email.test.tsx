import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  createOrganizationUser,
  issueOwnerSetupLink,
  useOrganizationUsers,
} from '../api/use-admin-organizations'
import { CreateFirstOwnerDialog } from '../components/create-first-owner-dialog'
import { OrganizationUsersSection } from '../components/organization-users-section'
import { OwnerInvitationSentNotice } from '../components/owner-invitation'
import { OrganizationSummary } from '../components/organization-summary'
import type { AdminOrganization, AdminOwnerInvitation } from '../types'

// An installation that cannot send email
// (api docs: architecture/organization-ownership-invitations.md, "Running without email").

vi.mock('../api/use-admin-organizations', () => ({
  createOrganizationUser: vi.fn(),
  issueOwnerSetupLink: vi.fn(),
  useOrganizationUsers: vi.fn(),
  resendOwnerInvitation: vi.fn(),
  cancelOwnerInvitation: vi.fn(),
}))
vi.mock('../api/use-limits', () => ({
  useTenantLimits: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('../api/use-admin-audit', () => ({
  useAdminAuditLogs: () => ({ data: undefined, isLoading: false, error: undefined }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const ACCEPT = 'https://app.example.com/ownership-invitations'

const NOT_SENT: AdminOwnerInvitation = {
  status: 'pending',
  invitee_email: 'person@example.com',
  send_count: 0,
  resends_left: 5,
  expires_at: '2099-01-01T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
  accept_url: ACCEPT,
}

const ORG: AdminOrganization = {
  id: 't1',
  name: 'Example Org',
  slug: 'example-org',
  created_at: '2026-10-01T00:00:00Z',
  active_members: 0,
  owner_emails: [],
  owner_domains: [],
  owner_count: 0,
  saml_enabled: false,
  active_identity_providers: 0,
  verified_domains: 0,
  sso_enforced: false,
  limits_apply: false,
  status: 'active',
  owner_invitation: NOT_SENT,
  email_delivery: false,
}

const users = (rows: unknown[]) =>
  ({
    data: { data: rows, total: rows.length, by_role: { owner: rows.length } },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }) as unknown as ReturnType<typeof useOrganizationUsers>

describe('Owners card without email', () => {
  it('says the invitation was not sent and offers the accept address to copy', () => {
    render(<OrganizationSummary org={ORG} onOpenTab={vi.fn()} />)
    expect(screen.getByTestId('owners-card-not-sent')).toHaveTextContent(
      'Not sent: this server cannot send email'
    )
    expect(screen.getByTestId('owner-invitation-accept-url')).toHaveTextContent(ACCEPT)
    expect(screen.getByRole('button', { name: /copy address/i })).toBeInTheDocument()
  })

  it('shows nothing extra when email works', () => {
    render(<OrganizationSummary org={{ ...ORG, email_delivery: true }} onOpenTab={vi.fn()} />)
    expect(screen.queryByTestId('owners-card-not-sent')).toBeNull()
  })
})

describe('Invitation notice without email', () => {
  it('never claims the person gets an invitation', () => {
    render(
      <OwnerInvitationSentNotice
        email="person@example.com"
        invitation={NOT_SENT}
        emailDelivery={false}
      />
    )
    expect(screen.queryByText(/they'll get an invitation/i)).toBeNull()
    expect(screen.getByTestId('owner-invitation-not-sent')).toHaveTextContent(/person@example.com/)
    expect(screen.getByTestId('owner-invitation-accept-url')).toHaveTextContent(ACCEPT)
  })
})

describe('Users tab without email', () => {
  beforeEach(() => vi.clearAllMocks())

  it('hides Send again, Last sent and Sends left for the invitation', () => {
    vi.mocked(useOrganizationUsers).mockReturnValue(users([]))
    render(
      <OrganizationUsersSection
        tenantId="t1"
        orgName="Example Org"
        canManage
        ownerInvitation={NOT_SENT}
        emailDelivery={false}
      />
    )
    expect(screen.queryByRole('button', { name: /send again/i })).toBeNull()
    expect(screen.queryByText('Last sent')).toBeNull()
    expect(screen.queryByText('Sends left')).toBeNull()
    expect(screen.getByTestId('owner-invitation-not-sent')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /change invitee/i })).toBeInTheDocument()
  })

  it('offers a new setup link for a new owner and shows the API address once', async () => {
    vi.mocked(useOrganizationUsers).mockReturnValue(
      users([
        {
          user_id: 'u1',
          email: 'new@example.com',
          name: 'New',
          role: 'owner',
          status: 'active',
          pending_setup: true,
          joined_at: '2026-10-01T00:00:00Z',
        },
      ])
    )
    vi.mocked(issueOwnerSetupLink).mockResolvedValue({
      user: { id: 'u1', email: 'new@example.com', name: 'New' },
      membership_id: 'm1',
      role: 'owner',
      email_sent: false,
      setup_token: 'tok',
      setup_url: 'https://app.example.com/set-password#token=tok',
      setup_expires_at: '2099-01-01T00:00:00Z',
    })
    const user = userEvent.setup()
    render(
      <OrganizationUsersSection
        tenantId="t1"
        orgName="Example Org"
        canManage
        emailDelivery={false}
      />
    )
    await user.click(screen.getByRole('button', { name: /new setup link/i }))
    await user.type(screen.getByLabelText('Reason'), 'The owner lost the first link')
    await user.click(screen.getByRole('button', { name: /create link/i }))
    await waitFor(() =>
      expect(issueOwnerSetupLink).toHaveBeenCalledWith('u1', 't1', 'The owner lost the first link')
    )
    expect(await screen.findByTestId('one-time-link')).toHaveTextContent(
      'https://app.example.com/set-password#token=tok'
    )
  })

  it('offers no setup link while email works, or to a role without the permission', () => {
    const row = {
      user_id: 'u1',
      email: 'new@example.com',
      name: 'New',
      role: 'owner',
      status: 'active',
      pending_setup: true,
      joined_at: '2026-10-01T00:00:00Z',
    }
    vi.mocked(useOrganizationUsers).mockReturnValue(users([row]))
    const { rerender } = render(
      <OrganizationUsersSection tenantId="t1" orgName="Example Org" canManage emailDelivery />
    )
    expect(screen.queryByRole('button', { name: /new setup link/i })).toBeNull()
    rerender(
      <OrganizationUsersSection
        tenantId="t1"
        orgName="Example Org"
        canManage={false}
        emailDelivery={false}
      />
    )
    expect(screen.queryByRole('button', { name: /new setup link/i })).toBeNull()
  })
})

describe('Change invitee without email', () => {
  it('says the invitation was created, not sent', async () => {
    vi.mocked(createOrganizationUser).mockResolvedValue({ owner_invitation: NOT_SENT })
    const user = userEvent.setup()
    render(
      <CreateFirstOwnerDialog
        tenantId="t1"
        changeInvitee
        emailDelivery={false}
        onCreated={vi.fn()}
      />
    )
    await user.click(screen.getByRole('button', { name: /change invitee/i }))
    await user.type(screen.getByLabelText('Name'), 'Person')
    await user.type(screen.getByLabelText('Email'), 'person@example.com')
    await user.click(screen.getByRole('button', { name: /^invite$/i }))
    expect(await screen.findByText('Invitation created')).toBeInTheDocument()
    expect(screen.queryByText('Invitation sent')).toBeNull()
    expect(screen.getByTestId('owner-invitation-accept-url')).toHaveTextContent(ACCEPT)
  })
})
