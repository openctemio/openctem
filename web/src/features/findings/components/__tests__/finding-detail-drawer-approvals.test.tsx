/**
 * The drawer's approval history: labels and dates in the app's language, and
 * member text (justification, rejection reason) as isolated plain text.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FindingDetailDrawer } from '../finding-detail-drawer'
import type { Finding } from '../../types'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (k: string, fallback?: string) =>
      k === 'findings.approvals.status.rejected' ? 'Bị từ chối' : (fallback ?? k),
    locale: 'vi',
  }),
}))
vi.mock('@/lib/permissions', () => ({
  useCanMutate: () => true,
  usePermissions: () => ({
    can: () => false,
    canAny: () => false,
    canAll: () => false,
    hasPermission: () => false,
  }),
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: new Proxy({}, { get: (_t, k) => String(k) }),
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: null }) }))
vi.mock('../detail/finding-people', () => ({ FindingPeople: () => null }))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({
    can: () => false,
    canAny: () => false,
    canAll: () => false,
    hasPermission: () => false,
  }),
}))
vi.mock('../detail/finding-approval-band', () => ({ FindingApprovalBand: () => null }))
vi.mock('@/features/remediation-hub/components/finding-task-band', () => ({
  FindingTaskBand: () => null,
}))
vi.mock('../../hooks/use-can-create-ticket', () => ({ useCanCreateTicket: () => false }))
vi.mock('../../api/use-findings-api', () => ({
  useFindingApi: () => ({ data: undefined }),
  useFindingApprovals: () => ({
    data: [
      {
        id: 'ap1',
        tenant_id: 't1',
        finding_id: 'f1',
        requested_status: 'false_positive',
        requested_by: 'u2',
        justification: 'safe\u202Eevil',
        rejection_reason: 'not\u202Eproven',
        status: 'rejected',
        created_at: new Date(Date.now() - 3 * 3600_000).toISOString(),
      },
    ],
  }),
}))
vi.mock('../../hooks/use-finding-triage', () => ({
  useFindingTriage: () => ({
    status: 'confirmed',
    severity: 'high',
    assignee: undefined,
    changeStatus: vi.fn(),
    changeSeverity: vi.fn(),
    changeAssignee: vi.fn(),
    dialogs: null,
  }),
}))
vi.mock('@/features/shared/components/detail-sheet-layout', () => ({
  DetailSheet: ({ header, children }: { header: React.ReactNode; children: React.ReactNode }) => (
    <div>
      {header}
      {children}
    </div>
  ),
  DetailHeader: ({ actions }: { actions: React.ReactNode }) => <div>{actions}</div>,
  DetailSheetFooter: () => null,
}))
vi.mock('../status-select', () => ({
  StatusSelect: (p: { disabled?: boolean }) => (
    <button data-testid="status" disabled={p.disabled} />
  ),
}))
vi.mock('../severity-select', () => ({
  SeveritySelect: (p: { disabled?: boolean }) => (
    <button data-testid="severity" disabled={p.disabled} />
  ),
}))
vi.mock('../assignee-select', () => ({
  AssigneeSelect: (p: { disabled?: boolean }) => (
    <button data-testid="assignee" disabled={p.disabled} />
  ),
}))

const finding = {
  id: 'f1',
  title: 'T',
  status: 'confirmed',
  severity: 'high',
  source: 'nuclei',
  assets: [],
  activities: [],
} as unknown as Finding

describe('FindingDetailDrawer approval history', () => {
  it('translates the status, dates in the locale and isolates member text', () => {
    render(<FindingDetailDrawer finding={finding} open onOpenChange={() => {}} />)
    expect(screen.getByText('Bị từ chối')).toBeInTheDocument()
    // Relative time in Vietnamese, not "3 hours ago".
    expect(document.body.textContent).toContain('3 giờ trước')
    const just = screen.getByText(/safe/)
    expect(just).toHaveAttribute('dir', 'auto')
    // The right-to-left override is shown as a visible escape, never applied.
    expect(just.textContent).not.toContain('\u202E')
    const reason = screen.getByText(/not/, { selector: 'span' })
    expect(reason).toHaveAttribute('dir', 'auto')
  })
})
