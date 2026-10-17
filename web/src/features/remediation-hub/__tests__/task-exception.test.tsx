/**
 * The task page's exception block: the pending exception (tier, sign-offs,
 * a link to the inbox) replaces the action; the action needs both
 * findings:remediation:write (the page's writable rule) and findings:write.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { useTaskException } from '../components/task-exception'

const state = vi.hoisted(() => ({
  perms: new Set<string>(['findings:read', 'findings:write', 'findings:remediation:write']),
  batch: undefined as Record<string, unknown> | undefined,
}))

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => state.perms.has(p) }),
}))

vi.mock('@/features/findings/api/use-approval-batches', () => ({
  usePendingTaskException: (_id: string, enabled: boolean) => ({
    batch: enabled ? state.batch : undefined,
    mutate: vi.fn(),
  }),
}))

vi.mock('@/features/findings/components/group-exception-dialog', () => ({
  GroupExceptionDialog: () => null,
}))

function Harness({ writable }: { writable: boolean }) {
  const ex = useTaskException('task-1', writable)
  return (
    <div>
      {ex.action}
      {ex.banner}
    </div>
  )
}

describe('useTaskException', () => {
  beforeEach(() => {
    state.perms = new Set(['findings:read', 'findings:write', 'findings:remediation:write'])
    state.batch = undefined
  })

  it('offers the action on a writable task without a pending exception', () => {
    render(<Harness writable />)
    expect(screen.getByRole('button', { name: 'Request exception' })).toBeInTheDocument()
  })

  it('hides the action without findings:write', () => {
    state.perms.delete('findings:write')
    render(<Harness writable />)
    expect(screen.queryByRole('button', { name: 'Request exception' })).not.toBeInTheDocument()
  })

  it('hides the action when the task is not writable', () => {
    render(<Harness writable={false} />)
    expect(screen.queryByRole('button', { name: 'Request exception' })).not.toBeInTheDocument()
  })

  it('shows the pending exception instead of the action', () => {
    state.batch = {
      id: 'b-1',
      requested_status: 'accepted',
      tier: 'dual',
      approvals_required: 2,
      approvals_collected: 1,
      member_count: 12,
      decide_by: '2026-10-23T00:00:00Z',
    }
    render(<Harness writable />)
    expect(screen.queryByRole('button', { name: 'Request exception' })).not.toBeInTheDocument()
    const banner = screen.getByTestId('task-pending-exception')
    expect(banner).toHaveTextContent('Exception pending: Accepted risk')
    expect(banner).toHaveTextContent('1 of 2 approvals')
    expect(banner).toHaveTextContent('12 finding(s)')
    expect(screen.getByRole('link', { name: 'Open in approvals' })).toHaveAttribute(
      'href',
      '/findings/approvals?view=groups&batch=b-1'
    )
  })

  it('does not look for a pending exception without findings:read', () => {
    state.perms.delete('findings:read')
    state.batch = { id: 'b-1', requested_status: 'accepted', tier: 'peer' }
    render(<Harness writable />)
    expect(screen.queryByTestId('task-pending-exception')).not.toBeInTheDocument()
  })
})
