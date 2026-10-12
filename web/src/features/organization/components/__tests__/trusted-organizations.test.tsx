import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const approve = vi.fn(async (_id: string, _attest: boolean) => ({}))
const remove = vi.fn(async (_id: string) => ({}))
const mutate = vi.fn()
let trusts: unknown[] = []
vi.mock('../../api/use-org-trusts', () => ({
  useOrgTrusts: () => ({ trusts, isLoading: false, error: undefined, mutate }),
  approveOrgTrust: (id: string, attest: boolean) => approve(id, attest),
  deleteOrgTrust: (id: string) => remove(id),
  createOrgTrust: vi.fn(),
  updateOrgTrust: vi.fn(),
}))

import { TrustedOrganizations } from '../trusted-organizations'

const base = {
  max_role: 'member',
  accept_home_sso: true,
  require_mfa_evidence: false,
  home_attests_mfa: false,
  allow_api_keys: false,
  created_at: '2026-10-01T00:00:00Z',
}

describe('TrustedOrganizations', () => {
  beforeEach(() => {
    approve.mockClear()
    remove.mockClear()
    trusts = [
      {
        ...base,
        id: 't1',
        direction: 'outgoing',
        organization: 'Partner Co',
        status: 'active',
        accepted_at: '2026-10-02T00:00:00Z',
      },
      {
        ...base,
        id: 't2',
        direction: 'incoming',
        organization: 'Sister Co',
        status: 'requested',
        max_role: 'viewer',
      },
    ]
  })

  it('lists trusts on both sides with their state', () => {
    render(<TrustedOrganizations canRead isOwner />)
    const rows = screen.getAllByTestId('org-trust-row')
    expect(rows).toHaveLength(2)
    expect(within(rows[0]).getByText('Partner Co')).toBeInTheDocument()
    expect(within(rows[0]).getByText('Active')).toBeInTheDocument()
    expect(within(rows[1]).getByText('Waiting for your approval')).toBeInTheDocument()
  })

  it('lets the owner of the home approve, attesting MFA', async () => {
    const user = userEvent.setup()
    render(<TrustedOrganizations canRead isOwner />)
    const incoming = screen.getAllByTestId('org-trust-row')[1]
    await user.click(within(incoming).getByRole('button', { name: 'Approve' }))
    await user.click(await screen.findByLabelText(/requires a second factor/))
    await user.click(screen.getAllByRole('button', { name: 'Approve' }).at(-1)!)
    expect(approve).toHaveBeenCalledWith('t2', true)
  })

  it('gives an administrator a read-only view', () => {
    render(<TrustedOrganizations canRead isOwner={false} />)
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Trust an organization/ })).toBeNull()
    expect(screen.getByText(/Only an owner can/)).toBeInTheDocument()
  })

  it('shows nothing to a member', () => {
    render(<TrustedOrganizations canRead={false} isOwner={false} />)
    expect(screen.queryAllByTestId('org-trust-row')).toHaveLength(0)
  })
})
