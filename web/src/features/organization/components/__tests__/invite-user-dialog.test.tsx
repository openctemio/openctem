import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiClientError } from '@/lib/api/error-handler'
import { useRoles } from '@/features/access-control/api/use-roles'
import { createTenantInvitation, previewInvitation } from '../../api/use-members'
import type { InvitationPreview } from '../../types/member.types'
import { InviteUserDialog, buildInvitationLink } from '../invite-user-dialog'

vi.mock('@/features/access-control/api/use-roles', () => ({ useRoles: vi.fn() }))
const { mockGroups } = vi.hoisted(() => ({
  mockGroups: { groups: [] as unknown[], isLoading: false },
}))
vi.mock('@/features/access-control/api/use-groups', () => ({ useGroups: () => mockGroups }))
vi.mock('../../api/use-members', () => ({
  createTenantInvitation: vi.fn(),
  previewInvitation: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const role = (id: string, name: string, slug = id, isSystem = true) => ({
  id,
  name,
  slug,
  description: '',
  is_system: isSystem,
  permission_count: 3,
  hierarchy_level: 0,
  has_full_data_access: false,
  permissions: [],
  summary: {
    risk: 'low' as const,
    reasons: [],
    areas: [{ area: 'findings', level: 'view' as const }],
  },
  created_at: '',
  updated_at: '',
})

const mockCreate = vi.mocked(createTenantInvitation)
const mockPreview = vi.mocked(previewInvitation)

const preview = (over: Partial<InvitationPreview> = {}): InvitationPreview => ({
  allowed: true,
  outside: false,
  personal: false,
  privileged: false,
  step_up_required: false,
  mfa_required: false,
  access_end_required: false,
  default_access_end_days: 90,
  max_access_end_days: 365,
  sso_exception_needed: false,
  already_member: false,
  already_invited: false,
  ...over,
})

// Radix measures itself inside a <form>; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

async function typeEmail(value = 'ann@co.com') {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('Email address'), value)
  return user
}

async function fillAndSend() {
  const user = await typeEmail()
  // The viewer role is preselected (least privilege).
  expect(screen.getByRole('radio', { name: 'Viewer' })).toBeChecked()
  await user.click(screen.getByRole('button', { name: /send invitation/i }))
}

describe('InviteUserDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGroups.groups = []
    mockPreview.mockResolvedValue(preview())
    vi.mocked(useRoles).mockReturnValue({
      roles: [role('r-viewer', 'Viewer', 'viewer')],
      isLoading: false,
    } as unknown as ReturnType<typeof useRoles>)
  })

  it('shows the invitation link from the create response, once', async () => {
    // The API keeps only a hash of the token: this response is the one place
    // the usable token appears.
    mockCreate.mockResolvedValue({
      id: 'inv1',
      email: 'ann@co.com',
      role: 'member',
      role_ids: ['r-viewer'],
      token: 'raw-token-abc',
      invited_by: 'u1',
      expires_at: '2026-10-08T00:00:00Z',
      created_at: '2026-10-01T00:00:00Z',
      pending: true,
    })
    const onInvited = vi.fn()
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} onInvited={onInvited} />)
    await fillAndSend()

    await waitFor(() =>
      expect(mockCreate).toHaveBeenCalledWith('acme', {
        email: 'ann@co.com',
        role_ids: ['r-viewer'],
      })
    )
    expect(await screen.findByText('Invitation created')).toBeInTheDocument()
    expect(screen.getByTestId('invitation-link')).toHaveTextContent(
      `${window.location.origin}/invitations#token=raw-token-abc`
    )
    expect(onInvited).toHaveBeenCalled()
  })

  it('says the invitation was emailed when the response has no token', async () => {
    mockCreate.mockResolvedValue({
      id: 'inv1',
      email: 'ann@co.com',
      role: 'member',
      role_ids: ['r-viewer'],
      invited_by: 'u1',
      expires_at: '2026-10-08T00:00:00Z',
      created_at: '2026-10-01T00:00:00Z',
      pending: true,
    })
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    await fillAndSend()
    expect(await screen.findByText('Invitation emailed')).toBeInTheDocument()
    expect(screen.queryByTestId('invitation-link')).toBeNull()
  })

  it('explains a refusal code in words and keeps the form', async () => {
    mockCreate.mockRejectedValue(new ApiClientError('already a member', 'ALREADY_MEMBER', 400))
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    await fillAndSend()
    expect(await screen.findByText('This person is already a member.')).toBeInTheDocument()
    expect(screen.getByLabelText('Email address')).toHaveValue('ann@co.com')
  })

  it('never shows a raw server message', async () => {
    mockCreate.mockRejectedValue(new ApiClientError('internal detail', 'SOMETHING_ELSE', 500))
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    await fillAndSend()
    expect(
      await screen.findByText('The invitation could not be created. Try again.')
    ).toBeInTheDocument()
    expect(screen.queryByText('internal detail')).toBeNull()
  })

  it('asks for a role when none is chosen', async () => {
    vi.mocked(useRoles).mockReturnValue({
      roles: [role('r-auditor', 'Auditor', 'auditor', false)],
      isLoading: false,
    } as unknown as ReturnType<typeof useRoles>)
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    const user = await typeEmail()
    await user.click(screen.getByRole('button', { name: /send invitation/i }))
    expect(await screen.findByText('Choose a role.')).toBeInTheDocument()
    expect(mockCreate).not.toHaveBeenCalled()
  })

  it('shows no error and no end-of-access field for an insider', async () => {
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    await typeEmail()
    await waitFor(() => expect(mockPreview).toHaveBeenCalled())
    expect(screen.queryByTestId('invite-refusal')).toBeNull()
    expect(screen.queryByTestId('invite-outside')).toBeNull()
    expect(screen.queryByLabelText(/end of access/i)).toBeNull()
  })

  it('guides, before sending, for someone outside the organization', async () => {
    mockPreview.mockResolvedValue(
      preview({
        outside: true,
        personal: true,
        privileged: true,
        step_up_required: true,
        mfa_required: true,
      })
    )
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    await typeEmail('pat@gmail.com')
    expect(await screen.findByTestId('invite-outside')).toHaveTextContent('Personal email address')
    expect(screen.getByTestId('invite-outside')).toHaveTextContent('two-factor authentication')
    expect(screen.getByTestId('invite-outside')).toHaveTextContent('confirm your identity')
    // Optional end of access, only for someone outside.
    expect(screen.getByLabelText('End of access (optional)')).toBeInTheDocument()
    expect(screen.queryByTestId('invite-refusal')).toBeNull()
    expect(screen.getByRole('button', { name: /send invitation/i })).toBeEnabled()
  })

  it('marks the end of access required when the organization requires it', async () => {
    mockPreview.mockResolvedValue(preview({ outside: true, access_end_required: true }))
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    await typeEmail('pat@gmail.com')
    expect(await screen.findByLabelText('End of access')).toBeInTheDocument()
    expect(screen.getByText(/90 days if you leave it empty/)).toBeInTheDocument()
  })

  it('states a policy refusal under the email and disables sending', async () => {
    mockPreview.mockResolvedValue(
      preview({ allowed: false, reason: 'INVITEE_NOT_ON_VERIFIED_DOMAIN', outside: true })
    )
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    await typeEmail('pat@gmail.com')
    expect(await screen.findByTestId('invite-refusal')).toHaveTextContent(
      'Your organization invites only addresses on its verified domains.'
    )
    expect(screen.getByRole('button', { name: /send invitation/i })).toBeDisabled()
  })
})

describe('InviteUserDialog roles', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPreview.mockResolvedValue(preview())
  })

  it('starts from the viewer role only, one primary role at a time', async () => {
    vi.mocked(useRoles).mockReturnValue({
      roles: [role('r-member', 'Member', 'member'), role('r-viewer', 'Viewer', 'viewer')],
      isLoading: false,
    } as unknown as ReturnType<typeof useRoles>)
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    expect(screen.getByRole('radio', { name: 'Viewer' })).toBeChecked()
    await userEvent.setup().click(screen.getByRole('radio', { name: 'Member' }))
    expect(screen.getByRole('radio', { name: 'Member' })).toBeChecked()
    expect(screen.getByRole('radio', { name: 'Viewer' })).not.toBeChecked()
  })

  it('adds custom roles on top of the primary role', async () => {
    vi.mocked(useRoles).mockReturnValue({
      roles: [role('r-viewer', 'Viewer', 'viewer'), role('r-auditor', 'Auditor', 'auditor', false)],
      isLoading: false,
    } as unknown as ReturnType<typeof useRoles>)
    mockCreate.mockResolvedValue({
      id: 'inv1',
      email: 'ann@co.com',
      role: 'member',
      role_ids: ['r-viewer', 'r-auditor'],
      invited_by: 'u1',
      expires_at: '2026-10-08T00:00:00Z',
      created_at: '2026-10-01T00:00:00Z',
      pending: true,
    })
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    const user = await typeEmail()
    await user.click(screen.getByRole('button', { name: /add another role/i }))
    await user.click(screen.getByRole('checkbox', { name: 'Auditor' }))
    await user.click(screen.getByRole('button', { name: /send invitation/i }))
    await waitFor(() =>
      expect(mockCreate).toHaveBeenCalledWith('acme', {
        email: 'ann@co.com',
        role_ids: ['r-viewer', 'r-auditor'],
      })
    )
  })

  it('shows what a role does instead of a permission count', () => {
    vi.mocked(useRoles).mockReturnValue({
      roles: [role('r-viewer', 'Viewer', 'viewer')],
      isLoading: false,
    } as unknown as ReturnType<typeof useRoles>)
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    expect(screen.getByTestId('role-risk-low')).toHaveTextContent('Low risk')
    expect(screen.getByText('Views Findings')).toBeInTheDocument()
    expect(screen.queryByText(/permissions$/)).toBeNull()
  })
})

describe('buildInvitationLink', () => {
  it('adds the invitee to the chosen teams and previews with them', async () => {
    mockGroups.groups = [
      { id: 'g-red', name: 'Red team', group_type: 'team', is_active: true },
      { id: 'g-old', name: 'Old team', group_type: 'team', is_active: false },
    ]
    mockCreate.mockResolvedValue({
      id: 'inv1',
      email: 'ann@co.com',
      role: 'member',
      role_ids: ['r-viewer'],
      invited_by: 'u1',
      expires_at: '2026-10-08T00:00:00Z',
      created_at: '2026-10-01T00:00:00Z',
      pending: true,
    })
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    expect(screen.queryByText('Old team')).toBeNull()
    const user = await typeEmail()
    await user.click(screen.getByRole('checkbox', { name: /red team/i }))
    await waitFor(() =>
      expect(mockPreview).toHaveBeenLastCalledWith(
        expect.objectContaining({ group_ids: ['g-red'] })
      )
    )
    await user.click(screen.getByRole('button', { name: /send invitation/i }))
    await waitFor(() =>
      expect(mockCreate).toHaveBeenCalledWith(
        'acme',
        expect.objectContaining({ group_ids: ['g-red'] })
      )
    )
  })

  it('explains a team the inviter cannot add people to', async () => {
    mockGroups.groups = [{ id: 'g-lead', name: 'Leads', group_type: 'team', is_active: true }]
    mockPreview.mockResolvedValue(preview({ allowed: false, reason: 'TEAM_NOT_GRANTABLE' }))
    render(<InviteUserDialog tenantSlug="acme" open onOpenChange={vi.fn()} />)
    const user = await typeEmail()
    await user.click(screen.getByRole('checkbox', { name: /leads/i }))
    expect(
      await screen.findByText('You cannot add people to one of these teams.')
    ).toBeInTheDocument()
  })

  it('points at the invitation page', () => {
    expect(buildInvitationLink('GWEu-eZWS_bit', 'https://x.test')).toBe(
      'https://x.test/invitations#token=GWEu-eZWS_bit'
    )
  })
})
