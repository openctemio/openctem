import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { FindingApprovalBand } from '../finding-approval-band'

let approvals: unknown[] | undefined
let userId: string | undefined
let perms: string[] = []
const cancel = vi.fn()
const mutate = vi.fn()
const lastKey = vi.fn()

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback?: string, vars?: Record<string, string>) =>
      (fallback ?? _k).replace(/\{(\w+)\}/g, (_m, v) => vars?.[v] ?? ''),
  }),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => perms.includes(p) }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { FindingsApprove: 'findings:approve', FindingsWrite: 'findings:write' },
}))
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: userId }) }))
vi.mock('@/components/link', () => ({
  default: ({ href, children, ...r }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...r}>
      {children}
    </a>
  ),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../../../api/use-findings-api', () => ({
  useFindingApprovals: (id: string | undefined) => {
    lastKey(id)
    return { data: approvals, mutate }
  },
  useCancelApproval: () => ({ trigger: cancel, isMutating: false }),
}))

const pending = {
  id: 'a1',
  tenant_id: 't',
  finding_id: 'f1',
  requested_status: 'false_positive',
  requested_by: 'req',
  requested_by_name: 'An Nguyen',
  justification: 'test-only route',
  status: 'pending',
  created_at: new Date().toISOString(),
}

beforeEach(() => {
  vi.clearAllMocks()
  approvals = [pending]
  perms = ['findings:write', 'findings:approve']
})

describe('FindingApprovalBand', () => {
  it('shows nothing without a pending request', () => {
    approvals = [{ ...pending, status: 'approved' }]
    const { container } = render(<FindingApprovalBand findingId="f1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('requests approvals for the finding whatever its status', () => {
    render(<FindingApprovalBand findingId="f1" />)
    expect(lastKey).toHaveBeenCalledWith('f1')
  })

  it('lets the requester cancel, and no one is sent to the inbox for their own request', async () => {
    userId = 'req'
    cancel.mockResolvedValue({})
    render(<FindingApprovalBand findingId="f1" />)
    expect(screen.getByText(/Requested by You/)).toBeInTheDocument()
    expect(screen.queryByTestId('finding-approval-decide-link')).toBeNull()
    fireEvent.click(screen.getByTestId('finding-approval-cancel'))
    expect(cancel).not.toHaveBeenCalled()
    fireEvent.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: 'Cancel request',
      })
    )
    await waitFor(() => expect(cancel).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(mutate).toHaveBeenCalled())
  })

  it('gives an approver the facts and the inbox link, but no cancel', () => {
    userId = 'approver'
    render(<FindingApprovalBand findingId="f1" />)
    expect(screen.getByText(/Requested by An Nguyen/)).toBeInTheDocument()
    expect(screen.getByText(/test-only route/)).toBeInTheDocument()
    expect(screen.queryByTestId('finding-approval-cancel')).toBeNull()
    expect(screen.getByTestId('finding-approval-decide-link')).toHaveAttribute(
      'href',
      '/findings/approvals'
    )
  })

  it('is read-only for another viewer: no cancel, no decision link', () => {
    userId = 'other'
    perms = ['findings:write']
    render(<FindingApprovalBand findingId="f1" />)
    expect(screen.getByTestId('finding-approval-band')).toBeInTheDocument()
    expect(screen.queryByTestId('finding-approval-cancel')).toBeNull()
    expect(screen.queryByTestId('finding-approval-decide-link')).toBeNull()
  })
})
