/**
 * The campaign list and detail on the task-program contract: status labels
 * from the one registry (a draft reads "Draft"), overdue as text, hidden tasks
 * as a count, a named findings progress bar, the buttons each status allows,
 * and the read-only state when the caller may not change the campaign.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { campaign, ownerNames } from './campaign-fixtures'
import type { RemediationCampaign } from '../../api/use-remediation-campaigns'

const state = vi.hoisted(() => ({
  perms: new Set<string>(['findings:remediation:read', 'findings:remediation:write']),
  list: [] as unknown[],
  counts: undefined as Record<string, number> | undefined,
  detail: undefined as unknown,
  tasks: [] as unknown[],
  setStatus: vi.fn(),
  push: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: state.push, replace: vi.fn() }),
  usePathname: () => '/remediation/campaigns',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => state.perms.has(p) }),
}))
vi.mock('@/features/remediation-hub/api/use-owner-names', () => ({
  useOwnerNames: () => ownerNames,
}))
vi.mock('@/features/remediation-hub/components/hub-page', () => ({
  HubPage: ({
    title,
    description,
    actions,
    children,
  }: {
    title: string
    description: string
    actions?: React.ReactNode
    children: React.ReactNode
  }) => (
    <main>
      <h1>{title}</h1>
      <p>{description}</p>
      {actions}
      {children}
    </main>
  ),
}))
vi.mock('@/features/remediation-hub/api/use-remediation-hub', () => ({
  useTasks: () => ({
    data: { data: state.tasks, total: state.tasks.length, page: 1, per_page: 25 },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useRevalidateHub: () => vi.fn(),
}))
vi.mock('../../api/use-remediation-campaigns', async (orig) => ({
  ...(await orig<typeof import('../../api/use-remediation-campaigns')>()),
  useRemediationCampaigns: () => ({
    data: { data: state.list, total: state.list.length, page: 1, per_page: 25 },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useCampaignStatusCounts: () => ({ data: state.counts }),
  useRemediationCampaign: () => ({ data: state.detail, isLoading: false, mutate: vi.fn() }),
  useRevalidateCampaigns: () => vi.fn(),
  useCreateCampaignTicket: () => ({ trigger: vi.fn(), isMutating: false }),
  campaignApi: {
    setStatus: state.setStatus,
    update: vi.fn(),
    create: vi.fn(),
    addTasks: vi.fn(),
    removeTask: vi.fn(),
    remove: vi.fn(),
  },
}))

import { CampaignList } from '../campaign-list'
import { CampaignDetail } from '../campaign-detail'

beforeEach(() => {
  state.perms = new Set(['findings:remediation:read', 'findings:remediation:write'])
  state.list = []
  state.counts = undefined
  state.detail = undefined
  state.tasks = []
  state.setStatus.mockReset()
})

describe('CampaignList', () => {
  it('shows each campaign with its status, owner, tasks and a named progress bar', () => {
    state.list = [
      campaign(),
      campaign({
        id: 'c-2',
        name: 'Patch critical',
        status: 'draft',
        is_overdue: true,
        due_date: '2020-01-01T00:00:00Z',
        assigned_team: undefined,
        summary: {
          ...campaign().summary,
          tasks: 0,
          overdue_tasks: 0,
          findings: 0,
          closed_findings: 0,
          hidden_tasks: 2,
        },
      }),
    ]
    state.counts = { all: 2, draft: 1, active: 1, completed: 0, canceled: 0 }
    render(<CampaignList />)
    expect(screen.getByRole('heading', { name: 'Campaigns' })).toBeInTheDocument()
    expect(screen.getAllByText('Active').length).toBeGreaterThan(0)
    // A draft reads "Draft", never "Open".
    expect(screen.getAllByText('Draft').length).toBeGreaterThan(0)
    expect(screen.queryByText('Open')).not.toBeInTheDocument()
    expect(
      screen.getAllByRole('progressbar', { name: '12 of 20 findings closed' }).length
    ).toBeGreaterThan(0)
    expect(screen.getAllByText(/overdue/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/2 hidden/).length).toBeGreaterThan(0)
    expect(screen.getAllByText('Sam · Ops').length).toBeGreaterThan(0)
    // Status counts come from the server, not from the page.
    const filters = screen.getByRole('tablist', { name: 'Filter by status' })
    expect(within(filters).getByRole('tab', { name: /Draft\s*1/ })).toBeInTheDocument()
  })

  it('offers "New campaign" in the empty state only with write access', () => {
    render(<CampaignList />)
    expect(screen.getByText('No campaigns yet')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'New campaign' }).length).toBe(2)
  })

  it('hides "New campaign" without write access', () => {
    state.perms.delete('findings:remediation:write')
    render(<CampaignList />)
    expect(screen.getByText('No campaigns yet')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'New campaign' })).not.toBeInTheDocument()
  })
})

function renderDetail(c: RemediationCampaign) {
  state.detail = c
  return render(<CampaignDetail campaignId={c.id} />)
}

describe('CampaignDetail', () => {
  it('starts a draft with the version it read', async () => {
    state.setStatus.mockResolvedValue(campaign())
    renderDetail(campaign({ status: 'draft' }))
    fireEvent.click(screen.getByRole('button', { name: 'Start' }))
    await waitFor(() =>
      expect(state.setStatus).toHaveBeenCalledWith('c-1', { status: 'active', version: 3 })
    )
  })

  it('disables Complete while tasks are still open, with the reason', () => {
    renderDetail(campaign())
    expect(screen.getByRole('button', { name: 'Complete' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Start' })).not.toBeInTheDocument()
  })

  it('completes an active campaign with no live task', async () => {
    state.setStatus.mockResolvedValue(campaign({ status: 'completed' }))
    renderDetail(campaign({ summary: { ...campaign().summary, live_tasks: 0 } }))
    fireEvent.click(screen.getByRole('button', { name: 'Complete' }))
    await waitFor(() =>
      expect(state.setStatus).toHaveBeenCalledWith('c-1', { status: 'completed', version: 3 })
    )
  })

  it('reopens a completed campaign', () => {
    renderDetail(campaign({ status: 'completed' }))
    expect(screen.getByRole('button', { name: 'Reopen' })).toBeInTheDocument()
    expect(screen.getAllByText('Completed').length).toBeGreaterThan(0)
  })

  it('is read-only when the caller may not change it', () => {
    renderDetail(campaign({ can_edit: false }))
    expect(screen.getByTestId('campaign-read-only')).toHaveTextContent(
      'outside your data scope, so you can view it but not change it'
    )
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'More actions' })).not.toBeInTheDocument()
  })

  it('shows no write action without findings:remediation:write', () => {
    state.perms.delete('findings:remediation:write')
    renderDetail(campaign())
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument()
    expect(screen.queryByTestId('campaign-read-only')).not.toBeInTheDocument()
  })

  it('counts tasks outside the data scope without listing them', () => {
    renderDetail(campaign({ summary: { ...campaign().summary, hidden_tasks: 2 } }))
    expect(screen.getByTestId('campaign-hidden-tasks')).toHaveTextContent(
      '2 tasks of this campaign are outside your data scope and are not listed.'
    )
  })

  it('shows the empty state with "Add tasks" when it has no task', () => {
    renderDetail(campaign({ summary: { ...campaign().summary, tasks: 0, live_tasks: 0 } }))
    expect(screen.getByText('This campaign has no tasks yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add tasks' })).toBeInTheDocument()
  })

  it('lists its tasks with their state from the registry and a remove action', () => {
    state.tasks = [
      {
        id: 't-1',
        title: 'Upgrade openssl',
        state: 'verifying',
        version: 1,
        counts: {
          total: 4,
          verified: 1,
          closed: 2,
          fix_applied: 1,
          open: 1,
          in_progress: 0,
          related: 0,
          risk_points: 3,
        },
      },
    ]
    renderDetail(campaign())
    const list = screen.getByRole('list', { name: 'Tasks of this campaign' })
    expect(within(list).getByText('Upgrade openssl')).toBeInTheDocument()
    expect(within(list).getByText('Verifying')).toBeInTheDocument()
    expect(
      within(list).getByRole('button', { name: 'Actions for Upgrade openssl' })
    ).toBeInTheDocument()
  })
})
