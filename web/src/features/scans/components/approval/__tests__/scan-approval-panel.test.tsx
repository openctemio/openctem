/**
 * The approval state on a scan's page (RFC-073 §8): hidden while Off;
 * Submit for approval asks for the evidence the rules need; the emergency
 * run is offered only to owners and administrators and needs a reason and
 * a window of 1 to 24 hours.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ScanApprovalStatusResponse } from '@/lib/api/scan-approval-hooks'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
const api = vi.hoisted(() => ({
  status: null as ScanApprovalStatusResponse | null,
  submit: vi.fn(),
  emergency: vi.fn(),
  mutate: vi.fn(),
}))
vi.mock('@/lib/api/scan-approval-hooks', () => ({
  useScanApprovalStatus: () => ({ data: api.status, mutate: api.mutate }),
  submitScanApproval: api.submit,
  emergencyRunScan: api.emergency,
}))
const role = vi.hoisted(() => ({ admin: false }))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ isOwner: () => false, isAdmin: () => role.admin, can: () => true }),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Permission: { ScansWrite: 'scans:write' },
}))
vi.mock('@/components/link', () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const { ScanApprovalPanel } = await import('../scan-approval-panel')

function status(over: Partial<ScanApprovalStatusResponse> = {}): ScanApprovalStatusResponse {
  return {
    mode: 'on',
    required: true,
    approved: false,
    changes: [],
    evaluation: {
      mode: 'on',
      required: true,
      approvals: 1,
      require_justification: true,
      matched: [{ id: 'r', name: 'Intrusive scans', requirement: { approvals: 1 } }],
    },
    ...over,
  }
}

beforeEach(() => {
  api.submit.mockReset().mockResolvedValue({})
  api.emergency.mockReset().mockResolvedValue({})
  role.admin = false
})

describe('ScanApprovalPanel', () => {
  it('renders nothing while scan approval is Off', () => {
    api.status = status({ mode: 'off' })
    const { container } = render(<ScanApprovalPanel scanId="s1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('submits with the justification the rules ask for', async () => {
    api.status = status()
    const user = userEvent.setup()
    render(<ScanApprovalPanel scanId="s1" />)
    expect(screen.getByText('Needs approval before it runs')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Emergency run/ })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Submit for approval' }))
    const submit = screen
      .getAllByRole('button', { name: 'Submit for approval' })
      .at(-1) as HTMLElement
    expect(submit).toBeDisabled()
    await user.type(screen.getByLabelText('Justification'), 'quarterly pentest')
    await user.click(submit)
    await waitFor(() =>
      expect(api.submit).toHaveBeenCalledWith('s1', {
        justification: 'quarterly pentest',
        ticket: '',
        run_on_approval: true,
      })
    )
  })

  it('offers an administrator an emergency run with a reason and a window', async () => {
    api.status = status()
    role.admin = true
    const onRan = vi.fn()
    const user = userEvent.setup()
    render(<ScanApprovalPanel scanId="s1" onRan={onRan} />)
    await user.click(screen.getByRole('button', { name: /Emergency run/ }))
    const run = screen.getByRole('button', { name: 'Run now' })
    expect(run).toBeDisabled()
    await user.type(screen.getByLabelText('Reason'), 'active incident')
    await user.click(run)
    await waitFor(() => expect(api.emergency).toHaveBeenCalledWith('s1', 'active incident', 4))
    expect(onRan).toHaveBeenCalled()
  })

  it('shows a waiting request and no submit or emergency', () => {
    api.status = status({
      current: { status: 'pending', remaining: 1 } as ScanApprovalStatusResponse['current'],
    })
    role.admin = true
    render(<ScanApprovalPanel scanId="s1" />)
    expect(screen.getByText('Waiting for approval')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Submit for approval' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open approvals' })).toHaveAttribute(
      'href',
      '/scans/approvals'
    )
  })

  it('shows an approved scan with no actions', () => {
    api.status = status({ approved: true })
    role.admin = true
    render(<ScanApprovalPanel scanId="s1" />)
    expect(screen.getByText('Approved')).toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })
})
