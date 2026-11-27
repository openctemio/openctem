/**
 * The fix plan is a ranked, server-paged table of open tasks. Its tiles count
 * on the server and filter the table; the running share of the list's risk
 * is shown only when it is exact (every task on screen, risk order), and is
 * otherwise a running total in points or nothing; a number that has not
 * arrived is a dash, never a 0.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

type Q = { data?: unknown; error?: unknown; isLoading?: boolean; mutate: () => void }
const s = vi.hoisted(() => ({
  calls: [] as Record<string, unknown>[],
  list: { mutate: () => {} } as Q,
  overdue: { mutate: () => {} } as Q,
  mine: { mutate: () => {} } as Q,
  open: { mutate: () => {} } as Q,
  push: vi.fn(),
}))

vi.mock('../components/task-sheet', () => ({
  TaskSheet: ({ taskId }: { taskId: string | null }) =>
    taskId ? <div data-testid="task-sheet">{taskId}</div> : null,
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: s.push, replace: vi.fn() }),
  usePathname: () => '/remediation',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))
vi.mock('../api/use-owner-names', () => ({
  useOwnerLabels: () => ({
    user: (id?: string) => (id ? 'Sam' : undefined),
    group: (id?: string) => (id ? 'Ops' : undefined),
  }),
}))
vi.mock('@/features/remediation/api/use-remediation-campaigns', () => ({
  useRemediationCampaigns: () => ({ data: undefined, isLoading: false, mutate: vi.fn() }),
}))
vi.mock('../api/use-remediation-hub', () => ({
  useTasks: (f: Record<string, unknown>, enabled = true) => {
    if (enabled) s.calls.push(f)
    if (f.perPage === 1) return f.overdue ? s.overdue : f.mine ? s.mine : s.open
    return s.list
  },
}))

import { FixPlan, planRows } from '../components/fix-plan'
import { VIEW_FILTERS } from '../components/task-views'

const counts = (total: number, risk: number) => ({
  total,
  open: total,
  in_progress: 0,
  fix_applied: 0,
  closed: 0,
  verified: 0,
  related: 0,
  risk_points: risk,
})
const task = (id: string, risk: number, extra: Record<string, unknown> = {}) => ({
  id,
  title: `Task ${id}`,
  action_title: 'Upgrade',
  state: 'open',
  deadline: '2099-01-01T00:00:00Z',
  deadline_source: 'member',
  counts: counts(2, risk),
  ...extra,
})
const page = (rows: unknown[], total = rows.length) => ({
  data: rows,
  total,
  page: 1,
  per_page: 25,
})

const value = (label: string) => {
  const el = screen.getByText(label, { selector: '[data-slot="metric-label"]' })
  return (el.parentElement as HTMLElement).querySelector('[data-slot="metric-value"]')!.textContent
}

beforeEach(() => {
  window.history.replaceState(null, '', '/remediation')
  s.calls.length = 0
  s.push.mockReset()
  s.list = { mutate: vi.fn(), data: page([task('a', 30), task('b', 20), task('c', 10)]) }
  s.overdue = { mutate: vi.fn(), data: page([], 2) }
  s.mine = { mutate: vi.fn(), data: page([], 4) }
  s.open = { mutate: vi.fn(), data: page([], 99) }
})

describe('planRows', () => {
  it('ranks from the page offset and keeps a running total only from rank 1', () => {
    const rows = [task('a', 5), task('b', 3)] as never[]
    expect(
      planRows(rows, { ranked: true, offset: 0 }).rows.map((r) => [r.rank, r.running])
    ).toEqual([
      [1, 5],
      [2, 8],
    ])
    expect(
      planRows(rows, { ranked: true, offset: 25 }).rows.map((r) => [r.rank, r.running])
    ).toEqual([
      [26, undefined],
      [27, undefined],
    ])
    expect(planRows(rows, { ranked: false, offset: 0 }).rows[0].rank).toBeUndefined()
  })
})

describe('fix plan', () => {
  it('sends the open tasks in risk order and counts the tiles on the server', () => {
    render(<FixPlan />)
    const table = s.calls.find((f) => f.perPage === 25)!
    expect(table.sort).toBe('risk')
    expect(table.states).toEqual(VIEW_FILTERS.open.states)
    // The open count is the table's own total while it shows the open tasks.
    expect(value('Open tasks')).toBe('3')
    expect(s.calls.some((f) => f.perPage === 1 && !f.overdue && !f.mine)).toBe(false)
    expect(value('Overdue')).toBe('2')
    expect(value('My tasks')).toBe('4')
  })

  it('shows the exact share when every task is on screen', () => {
    render(<FixPlan />)
    // 30 + 20 of 60 risk points.
    expect(screen.getAllByRole('meter', { name: /top 2 remove 83%/i }).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('meter', { name: /top 3 remove 100%/i }).length).toBeGreaterThan(0)
  })

  it('shows the running points, not a guessed share, when the list has more pages', () => {
    s.list.data = page([task('a', 30), task('b', 20)], 60)
    render(<FixPlan />)
    expect(screen.queryAllByRole('meter')).toHaveLength(0)
    expect(screen.getAllByText('50 points').length).toBeGreaterThan(0)
  })

  it('a tile filters the table instead of leaving the page', () => {
    render(<FixPlan />)
    fireEvent.click(screen.getByText('Overdue', { selector: '[data-slot="metric-label"]' }))
    expect(window.location.search).toContain('overdue=1')
    expect(s.calls.some((f) => f.perPage === 25 && f.overdue === true)).toBe(true)
    // Off the default view, the open count is its own request.
    expect(s.calls.some((f) => f.perPage === 1 && !f.overdue && !f.mine)).toBe(true)
    expect(value('Open tasks')).toBe('99')
  })

  it('shows a dash, not a zero, until a count arrives', () => {
    s.overdue = { mutate: vi.fn(), isLoading: true }
    render(<FixPlan />)
    expect(value('Overdue')).not.toBe('0')
  })

  it('marks a passed deadline with the compact overdue mark', () => {
    s.list.data = page([task('late', 5, { deadline: '2020-01-01T00:00:00Z' })])
    render(<FixPlan />)
    expect(document.querySelector('[data-slot="sla-countdown"]')?.textContent).toMatch(/overdue/)
  })

  it('a row opens the task quick view, not the page', () => {
    render(<FixPlan />)
    fireEvent.click(screen.getAllByText('Task b')[0])
    expect(s.push).not.toHaveBeenCalled()
    expect(window.location.search).toContain('task=b')
    expect(screen.getByTestId('task-sheet').textContent).toBe('b')
  })

  it('a ctrl click on the title keeps the full page link', () => {
    render(<FixPlan />)
    const link = screen.getAllByText('Task b')[0].closest('a')!
    expect(link.getAttribute('href')).toBe('/remediation/tasks/b')
    fireEvent.click(link, { ctrlKey: true })
    expect(window.location.search).not.toContain('task=')
  })

  it('progress uses the shared cell', () => {
    render(<FixPlan />)
    expect(document.querySelector('[data-slot="progress-cell"]')).not.toBeNull()
  })
})
