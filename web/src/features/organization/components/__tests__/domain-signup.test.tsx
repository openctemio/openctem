import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { DomainSignupPolicies } from '../domain-signup-policies'
import { JoinRequestsCard } from '../join-requests-card'
import * as api from '../../api/use-domain-signup'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../../api/use-domain-signup', async (orig) => ({
  ...(await orig<typeof import('../../api/use-domain-signup')>()),
  useDomainSignupPolicies: vi.fn(),
  saveDomainSignupPolicy: vi.fn(),
  useJoinRequests: vi.fn(),
  approveJoinRequest: vi.fn(),
  rejectJoinRequest: vi.fn(),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const domain: api.DomainSignupPolicy = {
  id: 'd1',
  domain: 'acme.example',
  status: 'verified',
  purpose: 'sso',
  effective: true,
  join_policy: 'off',
  join_role: 'viewer',
  discoverable: false,
  sso_required: false,
  block_new_workspaces: false,
  include_subdomains: false,
}

describe('DomainSignupPolicies', () => {
  beforeEach(() => vi.clearAllMocks())

  it('an owner opens joining with approval and saves', async () => {
    vi.mocked(api.useDomainSignupPolicies).mockReturnValue({
      domains: [domain],
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    } as never)
    vi.mocked(api.saveDomainSignupPolicy).mockResolvedValue(domain)
    const user = userEvent.setup()
    render(<DomainSignupPolicies canRead isOwner />)
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await user.click(screen.getByLabelText('Anyone, after an administrator approves'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(api.saveDomainSignupPolicy).toHaveBeenCalledWith(
        'd1',
        expect.objectContaining({ join_policy: 'approval', join_role: 'viewer' })
      )
    )
  })

  it('an admin reads but cannot change', () => {
    vi.mocked(api.useDomainSignupPolicies).mockReturnValue({
      domains: [domain],
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    } as never)
    render(<DomainSignupPolicies canRead isOwner={false} />)
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(screen.getByText('Only an owner can change these settings.')).toBeInTheDocument()
  })

  it('a claim not in effect locks every setting', () => {
    vi.mocked(api.useDomainSignupPolicies).mockReturnValue({
      domains: [{ ...domain, effective: false }],
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    } as never)
    render(<DomainSignupPolicies canRead isOwner />)
    expect(screen.getByText('Not in effect')).toBeInTheDocument()
    expect(screen.getByLabelText('Anyone, automatically')).toBeDisabled()
  })
})

describe('JoinRequestsCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('approves a request with the chosen role and hides when empty', async () => {
    const mutate = vi.fn()
    vi.mocked(api.useJoinRequests).mockReturnValue({
      requests: [
        {
          id: 'r1',
          email: 'bob@acme.example',
          name: 'Bob',
          email_verified: true,
          requested_role: 'viewer',
          requested_at: '2026-10-15T09:00:00Z',
          expires_at: '2026-11-14T09:00:00Z',
        },
      ],
      error: undefined,
      isLoading: false,
      mutate,
    } as never)
    vi.mocked(api.approveJoinRequest).mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<JoinRequestsCard canManage />)
    expect(screen.getByText('Requests to join (1)')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(api.approveJoinRequest).toHaveBeenCalledWith('r1', 'viewer'))

    vi.mocked(api.useJoinRequests).mockReturnValue({
      requests: [],
      error: undefined,
      isLoading: false,
      mutate,
    } as never)
    const { container } = render(<JoinRequestsCard canManage />)
    expect(container).toBeEmptyDOMElement()
  })
})
