/**
 * Adding findings to remediation from the findings list: a new task or an
 * existing open task; a 409 FINDINGS_IN_OTHER_TASK switches to the conflict
 * step, which retries with conflicts {skip} or {move, move_reason}. A task
 * the caller cannot read is never named.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { ApiClientError } from '@/lib/api/error-handler'
import { AddFindingsToTaskDialog } from '../components/add-findings-to-task-dialog'
import { claimConflicts } from '../lib/claim-conflicts'

const api = vi.hoisted(() => ({
  createTask: vi.fn(),
  addMembers: vi.fn(),
  push: vi.fn(),
  toast: vi.fn(),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: api.push }) }))
vi.mock('sonner', () => ({ toast: { success: api.toast, error: vi.fn() } }))
vi.mock('swr', () => ({
  default: (key: string | null) => ({
    data: key
      ? {
          data: [
            { id: 'c-1', name: 'Q4 TLS hardening', status: 'active' },
            { id: 'c-2', name: 'Old one', status: 'completed' },
          ],
        }
      : undefined,
  }),
}))
vi.mock('../api/use-owner-names', () => ({
  useOwnerNames: () => ({
    users: [{ id: 'u-1', name: 'Sam' }],
    groups: [{ id: 'g-1', name: 'Ops' }],
    user: (id?: string) => (id === 'u-1' ? 'Sam' : undefined),
    group: (id?: string) => (id === 'g-1' ? 'Ops' : undefined),
  }),
}))
vi.mock('../api/use-remediation-hub', () => ({
  hubApi: { createTask: api.createTask, addMembers: api.addMembers },
  useRevalidateHub: () => vi.fn(),
  useTasks: (_f: unknown, enabled: boolean) => ({
    data: enabled
      ? {
          data: [
            {
              id: 't-9',
              title: 'Upgrade openssl',
              state: 'in_progress',
              version: 4,
              assignee_user_id: 'u-1',
              counts: { total: 3 },
            },
          ],
          total: 1,
        }
      : undefined,
    isLoading: false,
  }),
}))

const conflictError = () =>
  new ApiClientError('findings are in other tasks', 'FINDINGS_IN_OTHER_TASK', 409, {
    conflicts: [
      {
        finding_id: 'f-1',
        finding_title: 'TLS 1.0 enabled',
        task_id: 't-2',
        task_title: 'Harden TLS',
        assignee_user_id: 'u-1',
        assignee_group_id: null,
        can_move: true,
      },
      {
        finding_id: 'f-2',
        finding_title: 'Weak cipher',
        task_id: 't-3',
        task_title: null,
        assignee_user_id: null,
        assignee_group_id: null,
        can_move: false,
      },
    ],
  })

const findings = [
  { id: 'f-1', title: 'TLS 1.0 enabled' },
  { id: 'f-2', title: 'Weak cipher' },
]

function renderDialog(list = findings) {
  const onDone = vi.fn()
  const onOpenChange = vi.fn()
  render(
    <AddFindingsToTaskDialog open onOpenChange={onOpenChange} findings={list} onDone={onDone} />
  )
  return { onDone, onOpenChange }
}

describe('AddFindingsToTaskDialog', () => {
  beforeEach(() => {
    api.createTask.mockReset()
    api.addMembers.mockReset()
    api.toast.mockReset()
  })

  it('prefills the title: the finding title for one, a count otherwise', () => {
    renderDialog([findings[0]])
    expect(screen.getByLabelText('Task title')).toHaveValue('TLS 1.0 enabled')
  })

  it('prefills a counted title for several findings', () => {
    renderDialog()
    expect(screen.getByLabelText('Task title')).toHaveValue('Fix 2 findings')
    expect(
      screen.getByRole('heading', { name: 'Add 2 findings to remediation' })
    ).toBeInTheDocument()
  })

  it('creates a task with the findings and closes', async () => {
    api.createTask.mockResolvedValue({ id: 't-1', title: 'Fix 2 findings' })
    const { onDone, onOpenChange } = renderDialog()
    fireEvent.click(screen.getByRole('button', { name: 'Create task' }))
    await waitFor(() => expect(onDone).toHaveBeenCalled())
    expect(api.createTask).toHaveBeenCalledWith({
      title: 'Fix 2 findings',
      finding_ids: ['f-1', 'f-2'],
    })
    expect(onOpenChange).toHaveBeenCalledWith(false)
    expect(api.toast).toHaveBeenCalledWith(
      'Task Fix 2 findings created',
      expect.objectContaining({ action: expect.objectContaining({ label: 'Open task' }) })
    )
  })

  it('shows the conflict step on 409 and never names a task the caller cannot read', async () => {
    api.createTask.mockRejectedValueOnce(conflictError())
    renderDialog()
    fireEvent.click(screen.getByRole('button', { name: 'Create task' }))
    const step = await screen.findByTestId('claim-conflict-step')
    expect(step).toHaveTextContent('2 findings are already in other open tasks.')
    expect(step).toHaveTextContent('In Harden TLS · Sam')
    expect(step).toHaveTextContent('In a task you cannot see')
    expect(step).not.toHaveTextContent('t-3')
    // Only the movable conflict offers "Move here".
    expect(screen.getAllByRole('checkbox')).toHaveLength(1)
  })

  it('skips the conflicts on retry', async () => {
    api.createTask.mockRejectedValueOnce(conflictError())
    api.createTask.mockResolvedValueOnce({ id: 't-1', title: 'Fix 2 findings' })
    const { onDone } = renderDialog()
    fireEvent.click(screen.getByRole('button', { name: 'Create task' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Skip these and continue' }))
    await waitFor(() => expect(onDone).toHaveBeenCalled())
    expect(api.createTask).toHaveBeenLastCalledWith(
      expect.objectContaining({ conflicts: { skip: true } })
    )
  })

  it('moves the selected findings only with a reason', async () => {
    api.createTask.mockRejectedValueOnce(conflictError())
    api.createTask.mockResolvedValueOnce({ id: 't-1', title: 'Fix 2 findings' })
    renderDialog()
    fireEvent.click(screen.getByRole('button', { name: 'Create task' }))
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Move here' }))
    const move = screen.getByRole('button', { name: 'Move selected (1)' })
    expect(move).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Reason for the move'), {
      target: { value: 'Same fix as the rest' },
    })
    fireEvent.click(move)
    await waitFor(() =>
      expect(api.createTask).toHaveBeenLastCalledWith(
        expect.objectContaining({
          conflicts: { move: ['f-1'], move_reason: 'Same fix as the rest' },
        })
      )
    )
  })

  it('adds to an existing task with its version', async () => {
    api.addMembers.mockResolvedValue({ id: 't-9', title: 'Upgrade openssl' })
    const { onDone } = renderDialog()
    fireEvent.mouseDown(screen.getByRole('tab', { name: 'Existing task' }))
    fireEvent.click(await screen.findByRole('option', { name: /Upgrade openssl/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Add to task' }))
    await waitFor(() => expect(onDone).toHaveBeenCalled())
    expect(api.addMembers).toHaveBeenCalledWith('t-9', {
      version: 4,
      finding_ids: ['f-1', 'f-2'],
    })
  })

  it('shows the API message on another error, such as a closed finding', async () => {
    api.createTask.mockRejectedValueOnce(
      new ApiClientError('finding f-1 is closed', 'BAD_REQUEST', 400)
    )
    renderDialog()
    fireEvent.click(screen.getByRole('button', { name: 'Create task' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('finding f-1 is closed')
  })
})

describe('claimConflicts', () => {
  it('ignores other errors', () => {
    expect(claimConflicts(new ApiClientError('x', 'CONFLICT', 409))).toBeNull()
    expect(claimConflicts(new Error('x'))).toBeNull()
  })

  it('reads an id-only answer as conflicts nobody may move', () => {
    const got = claimConflicts(
      new ApiClientError('x', 'FINDINGS_IN_OTHER_TASK', 409, { finding_ids: ['f-1'] }),
      new Map([['f-1', 'TLS 1.0 enabled']])
    )
    expect(got).toEqual([
      expect.objectContaining({
        finding_id: 'f-1',
        finding_title: 'TLS 1.0 enabled',
        task_title: null,
        can_move: false,
      }),
    ])
  })
})
