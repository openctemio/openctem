/**
 * The fix plan strip is honest: overdue is counted on the server over every
 * open task, a number that has not arrived is a dash and a failure is an
 * error with a retry, never zeros. Suggestion rows open that suggestion.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'

type Q = { data?: unknown; error?: unknown; isLoading?: boolean; mutate: () => void }
const mutate = vi.fn()
const taskCalls: Record<string, unknown>[] = []
const results: { open: Q; overdue: Q; mine: Q; sugg: Q; stats: Q } = {
  open: { mutate },
  overdue: { mutate },
  mine: { mutate },
  sugg: { mutate },
  stats: { mutate },
}

vi.mock('@/components/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))
vi.mock('../api/use-remediation-hub', () => ({
  useTasks: (f: Record<string, unknown>) => {
    taskCalls.push(f)
    if (f.overdue) return results.overdue
    if (f.mine) return results.mine
    return results.open
  },
  useSuggestions: () => results.sugg,
  useSuggestionStats: () => results.stats,
}))

import { FixPlan } from '../components/fix-plan'

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
const task = (id: string, total: number, risk: number) => ({
  id,
  title: `Task ${id}`,
  action_title: 'Upgrade',
  state: 'open',
  deadline: '2099-01-01T00:00:00Z',
  deadline_source: 'member',
  counts: counts(total, risk),
})
const page = (rows: unknown[], total = rows.length) => ({
  data: rows,
  total,
  page: 1,
  per_page: 25,
})

function ready() {
  results.open.data = page([task('a', 1, 4), task('b', 5, 20)], 60)
  results.overdue.data = page([], 37)
  results.mine.data = page([], 2)
  results.sugg.data = page([
    { id: 's1', kind: 'new_group', title: 'Rotate keys', risk_points: 12, member_count: 3 },
  ])
  results.stats.data = { proposed: 9 }
  for (const q of Object.values(results)) {
    q.error = undefined
    q.isLoading = false
  }
}

const value = (label: string) => {
  const dt = screen.getByText(label, { selector: 'dt' })
  return (dt.parentElement as HTMLElement).querySelector('dd')!.textContent
}

describe('fix plan', () => {
  beforeEach(() => {
    taskCalls.length = 0
    mutate.mockClear()
    ready()
  })

  it('counts overdue and open tasks on the server, not from the rows on screen', () => {
    render(<FixPlan />)
    expect(taskCalls.some((f) => f.overdue === true && f.perPage === 1)).toBe(true)
    expect(value('Overdue')).toBe('37')
    expect(value('Open tasks')).toBe('60')
    expect(value('Suggestions to review')).toBe('9')
    expect(value('My tasks')).toBe('2')
  })

  it('shows dashes, not zeros, until the numbers arrive', () => {
    results.open.data = undefined
    results.open.isLoading = true
    results.overdue.data = undefined
    results.overdue.isLoading = true
    render(<FixPlan />)
    expect(screen.queryByText('0')).toBeNull()
  })

  it('a failed read is an error with retry, not zeros', () => {
    results.overdue.data = undefined
    results.overdue.error = new Error('boom')
    render(<FixPlan />)
    expect(screen.getByText(/Failed to load the fix plan/)).toBeTruthy()
    expect(screen.queryByText('0')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /retry|try again/i }))
    expect(mutate).toHaveBeenCalled()
  })

  it('a suggestion row opens that suggestion; a task row opens the task', () => {
    render(<FixPlan />)
    const items = screen.getAllByRole('listitem')
    const sugg = items.find((li) => within(li).queryByText('Rotate keys'))!
    expect(within(sugg).getByRole('link').getAttribute('href')).toBe(
      '/remediation/suggestions?suggestion=s1'
    )
    const t = items.find((li) => within(li).queryByText('Task a'))!
    expect(within(t).getByRole('link').getAttribute('href')).toBe('/remediation/tasks/a')
  })

  it('uses singular and plural units', () => {
    render(<FixPlan />)
    const one = screen.getAllByRole('listitem').find((li) => within(li).queryByText('Task a'))!
    expect(one.textContent).toContain('1 finding · 4 risk points')
    const many = screen.getAllByRole('listitem').find((li) => within(li).queryByText('Task b'))!
    expect(many.textContent).toContain('5 findings · 20 risk points')
  })
})
