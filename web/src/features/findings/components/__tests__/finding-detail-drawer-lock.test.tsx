/**
 * The drawer locks status, severity and assignee for findings people wrote
 * (pentest, bug bounty, red team, manual), the same rule as the page's
 * properties rail; scanner findings stay editable.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FindingDetailDrawer } from '../finding-detail-drawer'
import type { Finding } from '../../types'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (_k: string, fallback?: string) => fallback ?? _k }),
}))
vi.mock('@/lib/permissions', () => ({ useCanMutate: () => true }))
vi.mock('../../hooks/use-can-create-ticket', () => ({ useCanCreateTicket: () => false }))
vi.mock('../../api/use-findings-api', () => ({
  useFindingApi: () => ({ data: undefined }),
  useFindingApprovals: () => ({ data: undefined }),
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

const row = (source: string) =>
  ({
    id: 'f1',
    title: 'T',
    status: 'confirmed',
    severity: 'high',
    source,
    assets: [],
    activities: [],
  }) as unknown as Finding

function open(source: string) {
  render(<FindingDetailDrawer finding={row(source)} open onOpenChange={() => {}} isLoading />)
}

beforeEach(() => vi.clearAllMocks())

describe('FindingDetailDrawer lock rules', () => {
  it.each(['pentest', 'bug_bounty', 'red_team', 'manual'])(
    'locks status, severity and assignee for a %s finding',
    (source) => {
      open(source)
      expect(screen.getByTestId('status')).toBeDisabled()
      expect(screen.getByTestId('severity')).toBeDisabled()
      expect(screen.getByTestId('assignee')).toBeDisabled()
    }
  )

  it('leaves a scanner finding editable', () => {
    open('sast')
    expect(screen.getByTestId('status')).toBeEnabled()
    expect(screen.getByTestId('severity')).toBeEnabled()
    expect(screen.getByTestId('assignee')).toBeEnabled()
  })
})
