import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { NotAffectedDialog } from '../components/not-affected-dialog'
import { AlertActions, OutOfScopeHint } from '../components/alert-actions'
import { splitTaskable, taskTitle } from '../types'
import { asset, detail } from './fixtures'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
// The mocked member holds every permission; the API is the authority.
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))

const wrap = (ui: React.ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

beforeEach(() => {
  api.post.mockReset()
})

describe('NotAffectedDialog', () => {
  it('needs a reason before it confirms, and explains the suppression', async () => {
    const onConfirm = vi.fn()
    render(
      <NotAffectedDialog
        open
        onOpenChange={() => {}}
        vulnId="CVE-2026-1000"
        onConfirm={onConfirm}
      />
    )
    expect(screen.getByText(/180 days/)).toBeInTheDocument()
    const confirm = screen.getByRole('button', { name: 'Mark not affected' })
    expect(confirm).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/Note/), 'checked on host')
    expect(confirm).toBeDisabled()
    await userEvent.click(screen.getByLabelText('The affected feature is not used'))
    expect(confirm).toBeEnabled()
    await userEvent.click(confirm)
    expect(onConfirm).toHaveBeenCalledWith('feature_not_used', 'checked on host')
  })

  it('limits the note to 500 characters', () => {
    render(<NotAffectedDialog open onOpenChange={() => {}} vulnId="x" onConfirm={() => {}} />)
    expect(screen.getByLabelText(/Note/)).toHaveAttribute('maxlength', '500')
  })
})

describe('AlertActions', () => {
  it('sends the chosen reason and note with the state change', async () => {
    api.post.mockResolvedValue(detail({ state: 'not_affected' }))
    wrap(<AlertActions alert={detail()} />)
    await userEvent.click(screen.getByRole('button', { name: 'Mark not affected' }))
    await userEvent.click(screen.getByLabelText('The match is the wrong product'))
    await userEvent.click(screen.getAllByRole('button', { name: 'Mark not affected' }).at(-1)!)
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/emerging-threats/a1/state', {
        state: 'not_affected',
        reason: 'wrong_product',
      })
    )
  })

  it('hides Mark not affected when the alert reaches outside the scope, and says why', () => {
    const alert = detail({ can_suppress: false })
    wrap(
      <>
        <AlertActions alert={alert} />
        <OutOfScopeHint alert={alert} />
      </>
    )
    expect(screen.queryByRole('button', { name: 'Mark not affected' })).toBeNull()
    expect(screen.getByText(/outside your scope/)).toBeInTheDocument()
  })

  it('acknowledges', async () => {
    api.post.mockResolvedValue(detail({ state: 'acknowledged' }))
    wrap(<AlertActions alert={detail()} />)
    await userEvent.click(screen.getByRole('button', { name: 'Acknowledge' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/emerging-threats/a1/state', {
        state: 'acknowledged',
      })
    )
  })
})

describe('create remediation task', () => {
  const mixed = detail({
    assets: [
      asset({ asset_id: 'e1', finding_id: 'f-open' }),
      asset({ asset_id: 'e2', finding_id: 'f-prog', finding_status: 'in_progress' }),
      asset({ asset_id: 'x1', finding_id: 'f-intask', task_id: 't9' }),
      asset({ asset_id: 'x2', finding_id: 'f-resolved', finding_status: 'resolved' }),
      asset({ asset_id: 'x3', finding_id: '', tier: 'possible' }),
    ],
  })

  it('splits eligible findings from the ones already in a task', () => {
    const { eligible, alreadyInTask } = splitTaskable(mixed.assets)
    expect(eligible.map((a) => a.finding_id)).toEqual(['f-open', 'f-prog'])
    expect(alreadyInTask.map((a) => a.finding_id)).toEqual(['f-intask'])
  })

  it('cuts the title to 200 characters', () => {
    expect(taskTitle('CVE-1', 'x'.repeat(500))).toHaveLength(200)
    expect(taskTitle('CVE-1', '')).toBe('CVE-1')
  })

  it('posts only the eligible finding ids and links the new task', async () => {
    api.post.mockResolvedValue({ id: 'task-42' })
    wrap(<AlertActions alert={mixed} />)
    await userEvent.click(screen.getByRole('button', { name: /Create remediation task/ }))
    expect(screen.getByText(/1 findings are already in a task/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Create task with 2 findings' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/remediation/tasks', {
        title: 'CVE-2026-1000: Remote code execution in Widget',
        finding_ids: ['f-open', 'f-prog'],
      })
    )
    const link = await screen.findByRole('link', { name: 'Open the task' })
    expect(link).toHaveAttribute('href', '/remediation/tasks/task-42')
  })

  it('shows the API message when a finding joined another task (409)', async () => {
    api.post.mockRejectedValue(
      Object.assign(new Error('finding already in a task'), { statusCode: 409 })
    )
    wrap(<AlertActions alert={mixed} />)
    await userEvent.click(screen.getByRole('button', { name: /Create remediation task/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Create task with 2 findings' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('finding already in a task')
  })

  it('is disabled when there is nothing to add', () => {
    wrap(
      <AlertActions
        alert={detail({ assets: [asset({ task_id: 't1' }), asset({ finding_id: '' })] })}
      />
    )
    expect(screen.getByRole('button', { name: /Create remediation task/ })).toBeDisabled()
    expect(api.post).not.toHaveBeenCalled()
  })
})
