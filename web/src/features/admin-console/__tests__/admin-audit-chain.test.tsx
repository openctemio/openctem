import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { AdminAuditChainStatusResponse } from '@/lib/api/generated'
import { AdminApiError } from '../api/admin-client'
import { rebaselineAuditChain, useAuditChainStatus } from '../api/use-admin-audit-chain'
import { OrganizationAuditChainPanel } from '../components/organization-audit-chain-panel'

vi.mock('../api/use-admin-audit-chain', async (orig) => ({
  ...(await orig<typeof import('../api/use-admin-audit-chain')>()),
  useAuditChainStatus: vi.fn(),
  rebaselineAuditChain: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const EXPLAINED: AdminAuditChainStatusResponse = {
  tenant_id: 't1',
  classified_at: '2026-10-02T10:00:00Z',
  total: 80,
  counts: {
    verifies: 70,
    legacy_truncate: 7,
    pre_79_nanosecond: 3,
    unexplained: 0,
    source_missing: 0,
    link_broken: 0,
  },
  breaks: 10,
  blocking: 0,
  last_position: 922,
  fingerprint: 'fp-reviewed',
  rebaseline_allowed: true,
  samples: [
    {
      position: 12,
      audit_log_id: 'a-12',
      action: 'settings.updated',
      logged_at: '2026-06-01T00:00:00Z',
      class: 'legacy_truncate',
    },
  ],
}

const UNEXPLAINED: AdminAuditChainStatusResponse = {
  ...EXPLAINED,
  counts: { ...EXPLAINED.counts, unexplained: 1 },
  breaks: 11,
  blocking: 1,
  rebaseline_allowed: false,
  fingerprint: 'fp-tampered',
  samples: [
    {
      position: 40,
      audit_log_id: 'a-40',
      action: 'asset.deleted',
      logged_at: '2026-07-01T00:00:00Z',
      class: 'unexplained',
    },
  ],
}

function mockStatus(data: AdminAuditChainStatusResponse) {
  const mutate = vi.fn()
  vi.mocked(useAuditChainStatus).mockReturnValue({
    data,
    error: undefined,
    isLoading: false,
    isValidating: false,
    mutate,
  } as unknown as ReturnType<typeof useAuditChainStatus>)
  return mutate
}

async function openAndConfirm(
  user: ReturnType<typeof userEvent.setup>,
  name: string,
  code: string
) {
  await user.click(screen.getByRole('button', { name: 'Rebaseline' }))
  const dialog = await screen.findByRole('alertdialog')
  await user.type(within(dialog).getByLabelText(/to confirm/i), name)
  await user.type(within(dialog).getByLabelText(/code from your authenticator/i), code)
  return dialog
}

describe('OrganizationAuditChainPanel', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the classification and the blocking rows, and refuses to offer a rebaseline', () => {
    mockStatus(UNEXPLAINED)
    render(<OrganizationAuditChainPanel tenantId="t1" orgName="Acme" canRebaseline />)
    expect(screen.getByText(/1 break no known defect explains/i)).toBeInTheDocument()
    expect(screen.getByText('a-40')).toBeInTheDocument()
    expect(screen.getByText('Unexplained', { selector: '[data-slot="badge"]' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Rebaseline' })).toBeDisabled()
    expect(screen.getByText(/refused while any break is unexplained/i)).toBeInTheDocument()
  })

  it('is review-only for administrators below super admin', () => {
    mockStatus(EXPLAINED)
    render(<OrganizationAuditChainPanel tenantId="t1" orgName="Acme" canRebaseline={false} />)
    expect(screen.getByText(/all explained by a known hashing defect/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Rebaseline' })).toBeDisabled()
    expect(screen.getByText(/requires a super admin/i)).toBeInTheDocument()
  })

  it('needs the organization name and a 6-digit code, then sends the reviewed fingerprint', async () => {
    const mutate = mockStatus(EXPLAINED)
    vi.mocked(rebaselineAuditChain).mockResolvedValue({
      ok: true,
      rebaseline_id: 'rb-1',
      entries_total: 81,
      entries_rewritten: 10,
      verify: { ok: true, total: 82, verified: 82, breaks: 0 },
    })
    const user = userEvent.setup()
    render(<OrganizationAuditChainPanel tenantId="t1" orgName="Acme" canRebaseline />)

    await user.click(screen.getByRole('button', { name: 'Rebaseline' }))
    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Rebaseline' })
    await user.type(within(dialog).getByLabelText(/code from your authenticator/i), '123456')
    expect(confirm).toBeDisabled() // name not typed yet
    await user.type(within(dialog).getByLabelText(/to confirm/i), 'Acme')
    expect(confirm).toBeEnabled()
    await user.click(confirm)

    await waitFor(() =>
      expect(rebaselineAuditChain).toHaveBeenCalledWith('t1', {
        fingerprint: 'fp-reviewed',
        totp_code: '123456',
      })
    )
    expect(await screen.findByText(/rebaselined: 10 of 81 entries re-signed/i)).toBeInTheDocument()
    expect(screen.getByText(/verification now passes/i)).toBeInTheDocument()
    expect(mutate).toHaveBeenCalled()
  })

  it('keeps the dialog open on a wrong code', async () => {
    mockStatus(EXPLAINED)
    vi.mocked(rebaselineAuditChain).mockRejectedValue(
      new AdminApiError('Invalid or already used code', 401, 'UNAUTHORIZED')
    )
    const user = userEvent.setup()
    render(<OrganizationAuditChainPanel tenantId="t1" orgName="Acme" canRebaseline />)
    const dialog = await openAndConfirm(user, 'Acme', '000000')
    await user.click(within(dialog).getByRole('button', { name: 'Rebaseline' }))
    expect(await within(dialog).findByText(/invalid or already used code/i)).toBeInTheDocument()
    expect(screen.getByRole('alertdialog')).toBeInTheDocument()
  })

  it('shows what the server saw when it refuses because the chain changed', async () => {
    const mutate = mockStatus(EXPLAINED)
    const seen = { ...EXPLAINED, fingerprint: 'fp-new', total: 81 }
    vi.mocked(rebaselineAuditChain).mockRejectedValue(
      new AdminApiError('The chain changed since you reviewed it', 409, 'AUDIT_CHAIN_CHANGED', seen)
    )
    const user = userEvent.setup()
    render(<OrganizationAuditChainPanel tenantId="t1" orgName="Acme" canRebaseline />)
    const dialog = await openAndConfirm(user, 'Acme', '123456')
    await user.click(within(dialog).getByRole('button', { name: 'Rebaseline' }))
    await waitFor(() => expect(mutate).toHaveBeenCalledWith(seen, { revalidate: false }))
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument())
  })

  it('has nothing to rebaseline when every entry verifies', () => {
    mockStatus({
      ...EXPLAINED,
      counts: { verifies: 80 },
      breaks: 0,
      samples: [],
    })
    render(<OrganizationAuditChainPanel tenantId="t1" orgName="Acme" canRebaseline />)
    expect(screen.queryByText(/known hashing defect/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Rebaseline' })).toBeDisabled()
    expect(screen.getByText(/nothing to rebaseline/i)).toBeInTheDocument()
  })
})
