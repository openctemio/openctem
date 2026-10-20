/**
 * The campaign dialogs: adding tasks (no-campaign list, the "other
 * campaigns" switch sends move, the 409 TASKS_IN_OTHER_CAMPAIGN step), and
 * the edit form (a stale save asks to reload, a refusal shows inline).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { ApiClientError } from '@/lib/api/error-handler'
import { campaign, ownerNames } from './campaign-fixtures'

const state = vi.hoisted(() => ({
  addTasks: vi.fn(),
  taskFilters: [] as Record<string, unknown>[],
}))

vi.mock('@/features/remediation-hub/api/use-owner-names', () => ({
  useOwnerNames: () => ownerNames,
}))
vi.mock('@/features/remediation-hub/api/use-remediation-hub', () => ({
  useTasks: (f: Record<string, unknown>) => {
    state.taskFilters.push(f)
    const free = {
      id: 't-1',
      title: 'Upgrade openssl',
      state: 'open',
      version: 1,
      counts: { total: 3 },
    }
    const other = {
      id: 't-2',
      title: 'Rotate keys',
      state: 'in_progress',
      version: 2,
      campaign_id: 'c-9',
      counts: { total: 1 },
    }
    return {
      data: { data: f.noCampaign ? [free] : [free, other], total: 2 },
      isLoading: false,
    }
  },
}))
vi.mock('../../api/use-remediation-campaigns', async (orig) => ({
  ...(await orig<typeof import('../../api/use-remediation-campaigns')>()),
  useRemediationCampaigns: () => ({ data: { data: [{ id: 'c-9', name: 'Legacy cleanup' }] } }),
  campaignApi: { addTasks: state.addTasks },
}))

import { AddTasksDialog } from '../add-tasks-dialog'
import { CampaignFormDialog } from '../campaign-form-dialog'

beforeEach(() => {
  state.addTasks.mockReset()
  state.taskFilters = []
})

describe('AddTasksDialog', () => {
  it('lists open tasks in no campaign and adds the picked ones', async () => {
    const onAdded = vi.fn()
    state.addTasks.mockResolvedValue(campaign())
    render(<AddTasksDialog campaign={campaign()} open onOpenChange={vi.fn()} onAdded={onAdded} />)
    expect(state.taskFilters.at(-1)).toMatchObject({ noCampaign: true })
    expect(screen.queryByText('Rotate keys')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: /Upgrade openssl/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Add 1 task' }))
    await waitFor(() => expect(onAdded).toHaveBeenCalled())
    expect(state.addTasks).toHaveBeenCalledWith('c-1', { task_ids: ['t-1'] })
  })

  it('moves a task from another campaign when the switch adds it', async () => {
    state.addTasks.mockResolvedValue(campaign())
    render(<AddTasksDialog campaign={campaign()} open onOpenChange={vi.fn()} onAdded={vi.fn()} />)
    fireEvent.click(screen.getByRole('switch', { name: 'Include tasks in other campaigns' }))
    expect(await screen.findByText(/In campaign Legacy cleanup/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: /Rotate keys/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Add 1 task' }))
    await waitFor(() =>
      expect(state.addTasks).toHaveBeenCalledWith('c-1', { task_ids: ['t-2'], move: true })
    )
  })

  it('shows the tasks in another campaign on 409 and moves only the movable ones', async () => {
    state.addTasks.mockRejectedValueOnce(
      new ApiClientError('in another campaign', 'TASKS_IN_OTHER_CAMPAIGN', 409, {
        tasks: [{ task_id: 't-1', campaign_id: 'c-7', campaign_name: null, can_move: true }],
      })
    )
    state.addTasks.mockResolvedValueOnce(campaign())
    render(<AddTasksDialog campaign={campaign()} open onOpenChange={vi.fn()} onAdded={vi.fn()} />)
    fireEvent.click(screen.getByRole('checkbox', { name: /Upgrade openssl/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Add 1 task' }))
    const step = await screen.findByTestId('tasks-in-other-campaign')
    expect(step).toHaveTextContent('Upgrade openssl')
    expect(step).toHaveTextContent('In a campaign you cannot see')
    fireEvent.click(screen.getByRole('button', { name: 'Move 1 task here' }))
    await waitFor(() =>
      expect(state.addTasks).toHaveBeenLastCalledWith('c-1', { task_ids: ['t-1'], move: true })
    )
  })
})

describe('CampaignFormDialog', () => {
  it('asks to reload after a stale save', async () => {
    const onReload = vi.fn()
    const onSubmit = vi
      .fn()
      .mockRejectedValue(new ApiClientError('version mismatch', 'CONFLICT', 409))
    render(
      <CampaignFormDialog
        open
        onOpenChange={vi.fn()}
        campaign={campaign()}
        onSubmit={onSubmit}
        onReload={onReload}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Someone else changed this campaign')
    fireEvent.click(screen.getByRole('button', { name: 'Reload' }))
    expect(onReload).toHaveBeenCalled()
  })

  it('shows a refusal inline, such as moving the due date later', async () => {
    const onSubmit = vi
      .fn()
      .mockRejectedValue(new ApiClientError('the due date cannot move later', 'BAD_REQUEST', 400))
    render(
      <CampaignFormDialog open onOpenChange={vi.fn()} campaign={campaign()} onSubmit={onSubmit} />
    )
    fireEvent.change(screen.getByLabelText('Due date'), { target: { value: '2099-12-31' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('the due date cannot move later')
    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'Q4 TLS hardening', due_date: '2099-12-31' })
    )
  })

  it('creates with a default medium priority and needs a name', () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined)
    render(<CampaignFormDialog open onOpenChange={vi.fn()} onSubmit={onSubmit} />)
    expect(screen.getByRole('button', { name: 'Create campaign' })).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Patch critical' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create campaign' }))
    expect(onSubmit).toHaveBeenCalledWith({
      name: 'Patch critical',
      description: '',
      priority: 'medium',
    })
  })
})
