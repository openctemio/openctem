/**
 * The finding's "tracked in task" band links to its task with the state and
 * deadline, and stays hidden without the permission, without a task, or when
 * the remediation API refuses (module off).
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const perms = { read: true }
const tasksResult: { data?: unknown; error?: unknown } = {}
const useTasks = vi.fn((_f: unknown, _enabled: boolean) => tasksResult)

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => perms.read }),
}))
vi.mock('../api/use-remediation-hub', () => ({
  useTasks: (f: unknown, enabled: boolean) => useTasks(f, enabled),
}))

import { FindingTaskBand } from '../components/finding-task-band'

const task = {
  id: 't1',
  title: 'Upgrade django to 4.2.30',
  state: 'in_progress',
  deadline: '2099-01-01T00:00:00Z',
  deadline_source: 'member',
  counts: {
    total: 3,
    open: 1,
    in_progress: 1,
    fix_applied: 1,
    closed: 0,
    verified: 0,
    related: 0,
    risk_points: 6,
  },
}

describe('FindingTaskBand', () => {
  beforeEach(() => {
    perms.read = true
    tasksResult.data = { data: [task], total: 1, page: 1, per_page: 3 }
    tasksResult.error = undefined
    useTasks.mockClear()
  })

  it('links to the task with its state', () => {
    render(<FindingTaskBand findingId="f1" />)
    expect(screen.getByRole('link', { name: 'Upgrade django to 4.2.30' })).toHaveAttribute(
      'href',
      '/remediation/tasks/t1'
    )
    expect(screen.getByText('In progress')).toBeInTheDocument()
    expect(useTasks).toHaveBeenCalledWith(expect.objectContaining({ findingId: 'f1' }), true)
  })

  it('does not ask without the permission', () => {
    perms.read = false
    const { container } = render(<FindingTaskBand findingId="f1" />)
    expect(container).toBeEmptyDOMElement()
    expect(useTasks).toHaveBeenCalledWith(expect.anything(), false)
  })

  it('hides when the finding is in no task or the API refuses', () => {
    tasksResult.data = { data: [], total: 0, page: 1, per_page: 3 }
    const { container, rerender } = render(<FindingTaskBand findingId="f1" />)
    expect(container).toBeEmptyDOMElement()
    tasksResult.data = undefined
    tasksResult.error = new Error('module off')
    rerender(<FindingTaskBand findingId="f1" />)
    expect(container).toBeEmptyDOMElement()
  })
})
