import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  approveAdminApproval,
  cancelAdminApproval,
  requestAdminApproval,
  useAdminApprovals,
} from '../api/use-admin-approvals'
import { AdminApprovalPrompt } from '../components/admin-approval-prompt'
import { approvalTargetLabel } from '../lib/approvals'
import type { AdminApproval, AdminApprovalList, AdminIdentity } from '../types'
import {
  AdminApiError,
  SECOND_APPROVAL_REQUIRED,
  adminFetch,
  setAdminApprovalPrompt,
} from '@console/lib/admin-api/client'
import ApprovalsPage from '@console/app/(console)/security/approvals/page'

const mocks = vi.hoisted(() => ({ admin: { current: null as AdminIdentity | null } }))

vi.mock('../components/admin-console-shell', () => ({ useAdmin: () => mocks.admin.current }))
vi.mock('../api/use-admin-approvals', () => ({
  useAdminApprovals: vi.fn(),
  approveAdminApproval: vi.fn(),
  rejectAdminApproval: vi.fn(),
  cancelAdminApproval: vi.fn(),
  requestAdminApproval: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('next/navigation', () => ({ usePathname: () => '/security/approvals' }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function approval(patch: Partial<AdminApproval>): AdminApproval {
  return {
    id: 'p1',
    action: 'admin.grant_super_admin',
    target: 'email:new@op.test',
    reason: 'New on-call lead',
    status: 'pending',
    requested_by_id: 'a2',
    requested_by_email: 'other@op.test',
    requested_at: '2026-10-18T08:00:00Z',
    expires_at: '2026-10-19T08:00:00Z',
    mine: false,
    ...patch,
  }
}

function mockList(list: Partial<AdminApprovalList>, mutate = vi.fn()) {
  vi.mocked(useAdminApprovals).mockReturnValue({
    data: {
      four_eyes: { active: true, approvers: 2, can_approve: true },
      ttl_hours: 24,
      data: [],
      ...list,
    },
    error: undefined,
    isLoading: false,
    mutate,
  } as unknown as ReturnType<typeof useAdminApprovals>)
  return mutate
}

function renderPage(role: AdminIdentity['role']) {
  mocks.admin.current = { id: 'a1', email: 'me@op.test', name: 'Me', role }
  return render(<ApprovalsPage />)
}

describe('Approvals page', () => {
  beforeEach(() => vi.clearAllMocks())

  it('is for super admins only (no request otherwise)', () => {
    mockList({})
    renderPage('ops_admin')
    expect(useAdminApprovals).toHaveBeenCalledWith(false)
    expect(screen.getByText(/only a super admin/i)).toBeInTheDocument()
  })

  it('explains how to turn approvals on when no other super admin can approve', () => {
    mockList({ four_eyes: { active: false, approvers: 1, can_approve: true } })
    renderPage('super_admin')
    expect(screen.getByText('Approvals are off')).toBeInTheDocument()
    expect(screen.getByText(/break-glass accounts do not count/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Add a super admin' })).toHaveAttribute(
      'href',
      '/security/administrators'
    )
  })

  it('never offers to approve your own request; approves another with a note', async () => {
    const user = userEvent.setup()
    const mutate = mockList({
      data: [
        approval({ id: 'mine', mine: true, requested_by_id: 'a1' }),
        approval({ id: 'theirs' }),
      ],
    })
    vi.mocked(approveAdminApproval).mockResolvedValue(
      approval({ id: 'theirs', status: 'approved' })
    )
    vi.mocked(cancelAdminApproval).mockResolvedValue(approval({ id: 'mine', status: 'canceled' }))
    renderPage('super_admin')

    expect(screen.getAllByRole('button', { name: /^approve$/i })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: /^withdraw$/i })).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: /^approve$/i }))
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText(/other@op.test asks: Make a super admin/)).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText(/^reason$/i), 'Confirmed by phone call')
    await user.click(within(dialog).getByRole('button', { name: /^approve$/i }))
    await waitFor(() =>
      expect(approveAdminApproval).toHaveBeenCalledWith('theirs', 'Confirmed by phone call')
    )
    await waitFor(() => expect(mutate).toHaveBeenCalled())

    await user.click(screen.getByRole('button', { name: /^withdraw$/i }))
    await waitFor(() => expect(cancelAdminApproval).toHaveBeenCalledWith('mine'))
  })

  it('a break-glass account may reject but not approve', () => {
    mockList({
      four_eyes: { active: true, approvers: 2, can_approve: false },
      data: [approval({})],
    })
    renderPage('super_admin')
    expect(screen.queryByRole('button', { name: /^approve$/i })).toBeNull()
    expect(screen.getByRole('button', { name: /^reject$/i })).toBeInTheDocument()
    expect(screen.getByText(/never approve/i)).toBeInTheDocument()
  })
})

describe('approval labels', () => {
  const t = (_k: string, f: string, v?: Record<string, string | number>) =>
    f.replace(/\{(\w+)\}/g, (_, n: string) => String(v?.[n] ?? ''))
  it('names targets without trusting anything but the server label', () => {
    expect(approvalTargetLabel({ target: 'email:a@op.test' }, t)).toBe('a@op.test')
    expect(approvalTargetLabel({ target: 'tenant:x', target_label: 'Acme' }, t)).toBe('Acme')
    expect(approvalTargetLabel({ target: 'mode=self_service;accounts=open' }, t)).toBe(
      'anyone may create an organization; anyone may create an account'
    )
    expect(approvalTargetLabel({ target: 'require_idp_off' }, t)).toBe(
      'Stop requiring the identity provider'
    )
  })
})

describe('second approval refusals', () => {
  const realFetch = globalThis.fetch
  beforeEach(() => vi.clearAllMocks())
  afterEach(() => {
    globalThis.fetch = realFetch
    setAdminApprovalPrompt(null)
  })

  function refuseWith428(details: Record<string, string>) {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            code: SECOND_APPROVAL_REQUIRED,
            message: 'Another super admin must approve this change first.',
            details,
          }),
          { status: 428, headers: { 'content-type': 'application/json' } }
        )
    ) as typeof fetch
  }

  it('opens the approval dialog and keeps the action refused', async () => {
    const seen = vi.fn()
    setAdminApprovalPrompt(seen)
    refuseWith428({ action: 'console_mfa.disable', target: 'off' })
    await expect(
      adminFetch('/settings/console-mfa/', { method: 'PUT', body: { require_webauthn: false } })
    ).rejects.toBeInstanceOf(AdminApiError)
    expect(seen).toHaveBeenCalledWith({ action: 'console_mfa.disable', target: 'off' })
  })

  it('asks another super admin with a reason from the dialog', async () => {
    const user = userEvent.setup()
    vi.mocked(requestAdminApproval).mockResolvedValue(approval({}))
    render(<AdminApprovalPrompt />)
    refuseWith428({ action: 'signup.open', target: 'mode=self_service;accounts=open' })
    await act(async () => {
      await adminFetch('/settings/signup/', { method: 'PUT', body: {} }).catch(() => undefined)
    })
    const dialog = await screen.findByRole('dialog')
    expect(
      within(dialog).getByText(/Open sign-up: anyone may create an organization/)
    ).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText(/^reason$/i), 'Public launch on Monday')
    await user.click(within(dialog).getByRole('button', { name: 'Ask for approval' }))
    await waitFor(() =>
      expect(requestAdminApproval).toHaveBeenCalledWith({
        action: 'signup.open',
        target: 'mode=self_service;accounts=open',
        reason: 'Public launch on Monday',
      })
    )
  })

  it('shows a request that is still waiting instead of asking again', async () => {
    render(<AdminApprovalPrompt />)
    refuseWith428({ action: 'platform_idp.remove', target: 'remove', pending_approval_id: 'p9' })
    await act(async () => {
      await adminFetch('/platform-idp/', { method: 'DELETE' }).catch(() => undefined)
    })
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Waiting for approval')).toBeInTheDocument()
    expect(within(dialog).getByRole('link', { name: 'Open approvals' })).toHaveAttribute(
      'href',
      '/security/approvals'
    )
    expect(requestAdminApproval).not.toHaveBeenCalled()
  })
})
