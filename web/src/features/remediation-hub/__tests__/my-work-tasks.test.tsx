/**
 * My Work: the Tasks tab lists the caller's open tasks (assignee=me, earliest
 * deadline first) and only exists for members who can read remediation tasks.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const perms = { read: true }
const search = { value: '' }
const replace = vi.fn()
const tasksResult: { data?: unknown; error?: unknown; isLoading?: boolean } = {}
const useTasks = vi.fn((_f: unknown, _enabled?: boolean) => ({ ...tasksResult, mutate: vi.fn() }))
const useFindingsApi = vi.fn((_f: unknown, _c?: unknown) => ({
  data: { data: [], total: 0 },
  isLoading: false,
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace }),
  useSearchParams: () => new URLSearchParams(search.value),
  usePathname: () => '/my-work',
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => perms.read }),
}))
vi.mock('@/features/remediation-hub/api/use-remediation-hub', () => ({
  useTasks: (f: unknown, enabled?: boolean) => useTasks(f, enabled),
}))
vi.mock('@/features/findings/api/use-findings-api', () => ({
  useFindingsApi: (f: unknown, c?: unknown) => useFindingsApi(f, c),
}))

import MyWorkPage from '@/app/(dashboard)/my-work/page'

const task = {
  id: 't1',
  title: 'Upgrade django to 4.2.30',
  action_title: 'Upgrade django',
  state: 'in_progress',
  deadline: '2099-01-01T00:00:00Z',
  deadline_source: 'member',
  counts: {
    total: 2,
    open: 1,
    in_progress: 1,
    fix_applied: 0,
    closed: 0,
    verified: 0,
    related: 0,
    risk_points: 4,
  },
}

describe('My Work tasks tab', () => {
  beforeEach(() => {
    perms.read = true
    search.value = ''
    tasksResult.data = { data: [task], total: 1, page: 1, per_page: 15 }
    tasksResult.error = undefined
    tasksResult.isLoading = false
    useTasks.mockClear()
    useFindingsApi.mockClear()
  })

  it('shows the findings queue by default with a Tasks tab', () => {
    render(<MyWorkPage />)
    expect(screen.getByRole('tab', { name: /Tasks/ })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Findings' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.queryByText('Upgrade django to 4.2.30')).not.toBeInTheDocument()
  })

  it('lists my open tasks by deadline on ?tab=tasks', () => {
    search.value = 'tab=tasks'
    render(<MyWorkPage />)
    const link = screen.getByRole('link', { name: 'Upgrade django to 4.2.30' })
    expect(link).toHaveAttribute('href', '/remediation/tasks/t1')
    // The fix is shown under the task only when it says something else.
    expect(screen.getByText('Upgrade django')).toBeInTheDocument()
    const queueCall = useTasks.mock.calls.find(
      ([f]) => (f as { sort?: string }).sort === 'deadline'
    )
    expect(queueCall?.[0]).toMatchObject({
      mine: true,
      sort: 'deadline',
      states: ['open', 'in_progress', 'verifying', 'on_hold'],
    })
    expect(screen.getByRole('link', { name: /View all tasks/ })).toHaveAttribute(
      'href',
      '/remediation/tasks?view=mine'
    )
    // The findings queries do not run while the Tasks tab is open.
    for (const [, cfg] of useFindingsApi.mock.calls) {
      expect(cfg).toMatchObject({ enabled: false })
    }
  })

  it('shows the empty state when nothing is assigned', () => {
    search.value = 'tab=tasks'
    tasksResult.data = { data: [], total: 0, page: 1, per_page: 15 }
    render(<MyWorkPage />)
    expect(screen.getByText('No open tasks')).toBeInTheDocument()
  })

  it('has no Tasks tab and no task query without remediation read', () => {
    perms.read = false
    search.value = 'tab=tasks'
    render(<MyWorkPage />)
    expect(screen.queryByRole('tab', { name: /Tasks/ })).not.toBeInTheDocument()
    for (const [, enabled] of useTasks.mock.calls) {
      expect(enabled).toBe(false)
    }
    expect(screen.queryByText('Upgrade django to 4.2.30')).not.toBeInTheDocument()
  })
})
