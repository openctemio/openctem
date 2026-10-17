import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { OnboardingOptions } from '@/features/auth/actions/local-auth-actions'
import { TeamOnboarding } from '../team-onboarding'

const options = vi.fn()
const accept = vi.fn()
vi.mock('@/features/auth/actions/local-auth-actions', () => ({
  onboardingOptionsAction: () => options(),
  onboardingAcceptAction: (ref: string) => accept(ref),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

// The form has its own tests; here we only care whether it is offered.
vi.mock('../create-team-form', () => ({
  CreateTeamForm: () => <form aria-label="create team form" />,
}))

const base: OnboardingOptions = {
  email_verified: true,
  invitations: [],
  organizations: [],
  can_create_organization: false,
  pending_requests: 0,
}

describe('TeamOnboarding (onboarding fork)', () => {
  beforeEach(() => {
    options.mockReset()
    accept.mockReset()
  })

  it('shows a spinner while the options load', () => {
    options.mockReturnValue(new Promise(() => {}))
    render(<TeamOnboarding hasOtherTeams={false} />)
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.queryByRole('form', { name: /create team form/i })).not.toBeInTheDocument()
  })

  it('offers the create form when the account may create an organization', async () => {
    options.mockResolvedValue({
      success: true,
      options: { ...base, can_create_organization: true },
    })
    render(<TeamOnboarding hasOtherTeams={false} />)
    expect(await screen.findByRole('form', { name: /create team form/i })).toBeInTheDocument()
    expect(screen.getByText('Set up your first team')).toBeInTheDocument()
  })

  it('tells an account with nothing offered to ask its administrator', async () => {
    options.mockResolvedValue({ success: true, options: base })
    render(<TeamOnboarding hasOtherTeams={false} />)
    expect(
      await screen.findByText('You are not a member of any organization yet')
    ).toBeInTheDocument()
    expect(screen.queryByRole('form', { name: /create team form/i })).not.toBeInTheDocument()
  })

  it('lists invitations and the organization of the verified domain, and asks to join by reference', async () => {
    options.mockResolvedValue({
      success: true,
      options: {
        ...base,
        invitations: [
          {
            ref: 'inv-ref',
            organization_name: 'Contoso',
            role: 'viewer',
            invited_by: 'Ann',
            expires_at: '2026-10-20T00:00:00Z',
          },
        ],
        organizations: [
          {
            ref: 'dom-ref',
            organization_name: 'Acme Corp',
            domain: 'acme.example',
            mode: 'request',
            pending: false,
          },
        ],
      },
    })
    accept.mockResolvedValue({ success: true, status: 'requested', organizationName: 'Acme Corp' })
    const user = userEvent.setup()
    render(<TeamOnboarding hasOtherTeams={false} />)
    expect(await screen.findByText('Contoso')).toBeInTheDocument()
    expect(screen.getByText('Invited by Ann as viewer')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Ask to join' }))
    await waitFor(() => expect(accept).toHaveBeenCalledWith('dom-ref'))
  })

  it('shows a pending request instead of the button', async () => {
    options.mockResolvedValue({
      success: true,
      options: {
        ...base,
        organizations: [
          {
            ref: 'r',
            organization_name: 'Acme Corp',
            domain: 'acme.example',
            mode: 'request',
            pending: true,
          },
        ],
      },
    })
    render(<TeamOnboarding hasOtherTeams={false} />)
    expect(await screen.findByText('Waiting for approval')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Ask to join' })).not.toBeInTheDocument()
  })

  it('asks an unverified account to verify first', async () => {
    options.mockResolvedValue({ success: true, options: { ...base, email_verified: false } })
    render(<TeamOnboarding hasOtherTeams={false} />)
    expect(await screen.findByText(/verify your email address/i)).toBeInTheDocument()
  })
})
