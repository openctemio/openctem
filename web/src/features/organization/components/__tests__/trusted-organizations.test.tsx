import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const approve = vi.fn(async (_id: string, _attest: boolean) => ({}))
const remove = vi.fn(async (_id: string) => ({}))
const mutate = vi.fn()
const update = vi.fn(async (_id: string, _input: unknown) => ({}))
let trusts: unknown[] = []
vi.mock('../../api/use-org-trusts', () => ({
  useOrgTrusts: () => ({ trusts, isLoading: false, error: undefined, mutate }),
  approveOrgTrust: (id: string, attest: boolean) => approve(id, attest),
  deleteOrgTrust: (id: string) => remove(id),
  createOrgTrust: vi.fn(),
  updateOrgTrust: (id: string, input: unknown) => update(id, input),
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

  it('ends a trust only after typing the organization name', async () => {
    const user = userEvent.setup()
    render(<TrustedOrganizations canRead isOwner />)
    const outgoing = screen.getAllByTestId('org-trust-row')[0]
    await user.click(within(outgoing).getByRole('button', { name: /End trust with Partner Co/ }))
    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'End trust' })
    expect(confirm).toBeDisabled()
    await user.type(within(dialog).getByRole('textbox'), 'Partner Co')
    await user.click(confirm)
    expect(remove).toHaveBeenCalledWith('t1')
  })

  it('asks before a setting change that makes the trust weaker', async () => {
    const user = userEvent.setup()
    render(<TrustedOrganizations canRead isOwner />)
    const outgoing = screen.getAllByTestId('org-trust-row')[0]
    await user.click(within(outgoing).getByRole('button', { name: 'Settings' }))
    const edit = await screen.findByRole('dialog')
    // Allowing API keys loosens the trust.
    await user.click(within(edit).getByRole('switch', { name: /API keys/i }))
    await user.click(within(edit).getByRole('button', { name: 'Save' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Loosen the trust with Partner Co?')
    expect(update).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('button', { name: 'Save weaker trust' }))
    expect(update).toHaveBeenCalledWith('t1', expect.objectContaining({ allow_api_keys: true }))
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
