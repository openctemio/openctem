/**
 * The drawer's header shows the finding's place in the list it was opened
 * from ("3 of 418") with previous / next; without a list there is none.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingDetailDrawer } from '../finding-detail-drawer'
import type { Finding } from '../../types'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    locale: 'en',
    t: (k: string, fallback?: string, vars?: Record<string, string>) =>
      (fallback ?? k).replace(/\{(\w+)\}/g, (_m, name: string) => vars?.[name] ?? ''),
  }),
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

const finding = {
  id: 'f1',
  title: 'T',
  status: 'confirmed',
  severity: 'high',
  source: 'sast',
  assets: [],
  activities: [],
} as unknown as Finding

function open(listNav?: React.ComponentProps<typeof FindingDetailDrawer>['listNav']) {
  render(
    <FindingDetailDrawer
      finding={finding}
      open
      onOpenChange={() => {}}
      isLoading
      listNav={listNav}
    />
  )
}

beforeEach(() => vi.clearAllMocks())

describe('FindingDetailDrawer position in the list', () => {
  it('shows "n of N" with grouped digits and announces a change politely', () => {
    open({ index: 1203, total: 12418, onPrev: vi.fn(), onNext: vi.fn() })
    const position = screen.getByRole('status')
    expect(position).toHaveTextContent('1,203 of 12,418')
    expect(position).toHaveAttribute('aria-live', 'polite')
    expect(position).toHaveAttribute('data-slot', 'finding-drawer-position')
    expect(position.className).toContain('tabular-nums')
  })

  it('previous and next make the list moves', async () => {
    const onPrev = vi.fn()
    const onNext = vi.fn()
    open({ index: 2, total: 418, onPrev, onNext })
    await userEvent.click(screen.getByRole('button', { name: 'Next finding' }))
    expect(onNext).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByRole('button', { name: 'Previous finding' }))
    expect(onPrev).toHaveBeenCalledTimes(1)
  })

  it('disables previous at the first row and next at the last', () => {
    open({ index: 1, total: 1 })
    expect(screen.getByRole('button', { name: 'Previous finding' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Next finding' })).toBeDisabled()
  })

  it('shows no position when the drawer was not opened from a list row', () => {
    open(undefined)
    expect(screen.queryByRole('status')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Next finding' })).toBeNull()
    expect(screen.queryByRole('navigation')).toBeNull()
  })
})
