import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  cancelOwnerInvitation,
  createOrganization,
  createOrganizationUser,
  resendOwnerInvitation,
  useOrganizationUsers,
} from '../api/use-admin-organizations'
import { CreateFirstOwnerDialog } from '../components/create-first-owner-dialog'
import { CreateOrganizationDialog } from '../components/create-organization-dialog'
import { OrganizationUsersSection } from '../components/organization-users-section'
import type { AdminOwnerInvitation } from '../types'

// Ownership invitations in the console
// (api docs: architecture/organization-ownership-invitations.md).

vi.mock('../api/use-admin-organizations', () => ({
  createOrganization: vi.fn(),
  createOrganizationUser: vi.fn(),
  useOrganizationUsers: vi.fn(),
  resendOwnerInvitation: vi.fn(),
  cancelOwnerInvitation: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const INVITATION: AdminOwnerInvitation = {
  status: 'pending',
  invitee_email: 'person@example.com',
  send_count: 1,
  resends_left: 4,
  resend_available_at: '2026-01-01T00:00:00Z',
  expires_at: '2099-01-01T00:00:00Z',
  last_sent_at: '2026-01-01T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
}

const ORG = {
  id: 't1',
  name: 'VNDS',
  slug: 'vnds',
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
  status: 'active' as const,
}

const noUsers = () =>
  ({
    data: { data: [], total: 0 },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }) as unknown as ReturnType<typeof useOrganizationUsers>

describe('New organization for an existing account', () => {
  beforeEach(() => vi.clearAllMocks())

  it('creates the organization and says the person gets an invitation (no red refusal)', async () => {
    vi.mocked(createOrganization).mockResolvedValue({
      ...ORG,
      owner_invited: true,
      owner_invitation: INVITATION,
    })
    const onCreated = vi.fn()
    const user = userEvent.setup()
    render(<CreateOrganizationDialog onCreated={onCreated} />)
    await user.click(screen.getByRole('button', { name: /new organization/i }))
    await user.type(screen.getByLabelText('Name'), 'VNDS')
    await user.type(screen.getByLabelText('Owner email'), 'person@example.com')
    await user.click(screen.getByRole('button', { name: /create organization/i }))

    expect(
      await screen.findByText(
        "This person already has an account. They'll get an invitation to become the owner."
      )
    ).toBeInTheDocument()
    expect(onCreated).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Done' }))
    expect(onCreated).toHaveBeenCalledWith(expect.objectContaining({ id: 't1' }))
  })
})

describe('Users tab of an organization waiting for its owner', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useOrganizationUsers).mockReturnValue(noUsers())
  })

  it('shows the invitation with its actions instead of "Create first owner"', () => {
    render(
      <OrganizationUsersSection
        tenantId="t1"
        orgName="VNDS"
        canManage
        ownerInvitation={INVITATION}
      />
    )
    expect(screen.getAllByText('Waiting for owner to accept').length).toBeGreaterThan(0)
    expect(screen.getByText('Invited: person@example.com')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /send again/i })).toBeEnabled()
    expect(screen.getByRole('button', { name: /change invitee/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /cancel invitation/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /create first owner/i })).toBeNull()
  })

  it('sends the invitation again and refreshes', async () => {
    vi.mocked(resendOwnerInvitation).mockResolvedValue({ owner_invitation: INVITATION })
    const onChanged = vi.fn()
    const user = userEvent.setup()
    render(
      <OrganizationUsersSection
        tenantId="t1"
        orgName="VNDS"
        canManage
        ownerInvitation={INVITATION}
        onChanged={onChanged}
      />
    )
    await user.click(screen.getByRole('button', { name: /send again/i }))
    await waitFor(() => expect(resendOwnerInvitation).toHaveBeenCalledWith('t1'))
    expect(onChanged).toHaveBeenCalled()
  })

  it('cancels after confirmation', async () => {
    vi.mocked(cancelOwnerInvitation).mockResolvedValue({
      owner_invitation: { ...INVITATION, status: 'canceled' },
    })
    const user = userEvent.setup()
    render(
      <OrganizationUsersSection
        tenantId="t1"
        orgName="VNDS"
        canManage
        ownerInvitation={INVITATION}
      />
    )
    await user.click(screen.getByRole('button', { name: /cancel invitation/i }))
    const buttons = await screen.findAllByRole('button', { name: /cancel invitation/i })
    await user.click(buttons[buttons.length - 1])
    await waitFor(() => expect(cancelOwnerInvitation).toHaveBeenCalledWith('t1'))
  })

  it('disables "Send again" when no send is left, and hides actions without permission', () => {
    const { rerender } = render(
      <OrganizationUsersSection
        tenantId="t1"
        orgName="VNDS"
        canManage
        ownerInvitation={{ ...INVITATION, resends_left: 0, resend_available_at: undefined }}
      />
    )
    expect(screen.getByRole('button', { name: /send again/i })).toBeDisabled()
    rerender(
      <OrganizationUsersSection
        tenantId="t1"
        orgName="VNDS"
        canManage={false}
        ownerInvitation={INVITATION}
      />
    )
    expect(screen.queryByRole('button', { name: /send again/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /cancel invitation/i })).toBeNull()
  })

  it('change invitee to an existing account shows the invitation result', async () => {
    vi.mocked(createOrganizationUser).mockResolvedValue({
      owner_invitation: { ...INVITATION, invitee_email: 'other@example.com' },
    })
    const user = userEvent.setup()
    render(<CreateFirstOwnerDialog tenantId="t1" changeInvitee onCreated={vi.fn()} />)
    await user.click(screen.getByRole('button', { name: /change invitee/i }))
    await user.type(screen.getByLabelText('Name'), 'Other')
    await user.type(screen.getByLabelText('Email'), 'other@example.com')
    await user.click(screen.getByRole('button', { name: /^invite$/i }))
    expect(await screen.findByText('Invitation sent')).toBeInTheDocument()
  })
})
