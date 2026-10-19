import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { TaskQueryPanel } from '../components/task-query-panel'
import type { TaskQuery } from '../api/use-task-query'

const api = vi.hoisted(() => ({
  query: null as TaskQuery | null,
  previewRerun: vi.fn(),
  rerun: vi.fn(),
  setAuto: vi.fn(),
  mutate: vi.fn(),
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../api/use-owner-names', () => ({
  useOwnerNames: () => ({
    users: [],
    groups: [],
    user: (id?: string) => (id === 'u-1' ? 'Sam' : undefined),
    group: () => undefined,
  }),
}))
vi.mock('../api/use-task-query', async (orig) => {
  const real = await orig<typeof import('../api/use-task-query')>()
  return {
    ...real,
    useTaskQuery: () => ({ data: api.query, mutate: api.mutate }),
    taskQueryApi: {
      ...real.taskQueryApi,
      previewRerun: api.previewRerun,
      rerun: api.rerun,
      setAuto: api.setAuto,
    },
  }
})

const base: TaskQuery = {
  task_id: 't-1',
  query: 'findings where severity = critical',
  query_version: 2,
  mode: 'snapshot',
  auto_state: null,
  auto_reason: null,
  cap: 1000,
  owner_user_id: 'u-1',
  last_run_at: null,
  last_added_count: 0,
  total_added: 0,
  created_at: '2026-10-19T00:00:00Z',
}

describe('TaskQueryPanel', () => {
  beforeEach(() => {
    api.previewRerun.mockReset()
    api.rerun.mockReset()
    api.setAuto.mockReset()
  })

  it('renders nothing for a task not created from a query', () => {
    api.query = null
    const { container } = render(<TaskQueryPanel taskId="t-1" writable />)
    expect(container).toBeEmptyDOMElement()
  })

  it('re-runs only after confirmation', async () => {
    api.query = base
    const onChanged = vi.fn()
    render(<TaskQueryPanel taskId="t-1" writable onChanged={onChanged} />)
    expect(screen.getByTestId('task-query-panel')).toHaveTextContent(
      'findings where severity = critical'
    )
    expect(screen.getByTestId('task-query-panel')).toHaveTextContent('Runs as Sam.')
    api.previewRerun.mockResolvedValue({ query: base.query, new: 2, truncated: false, room: 998 })
    fireEvent.click(screen.getByRole('button', { name: 'Re-run query' }))
    expect(
      await screen.findByText('2 new findings match and no other task holds them.')
    ).toBeInTheDocument()
    expect(api.rerun).not.toHaveBeenCalled()
    api.rerun.mockResolvedValue({ task: {}, added: 2, skipped: 0, capped: 0 })
    fireEvent.click(screen.getByRole('button', { name: 'Add 2' }))
    await waitFor(() => expect(api.rerun).toHaveBeenCalledWith('t-1'))
    expect(onChanged).toHaveBeenCalled()
  })

  it('shows a suspension with its reason and offers resume', async () => {
    api.query = {
      ...base,
      mode: 'auto',
      auto_state: 'suspended',
      auto_reason: 'owner_removed',
      owner_user_id: null,
    }
    render(<TaskQueryPanel taskId="t-1" writable />)
    expect(screen.getByText('Suspended')).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('left the organization')
    expect(screen.getByTestId('task-query-panel')).toHaveTextContent('Runs as a former member.')
    expect(screen.queryByRole('button', { name: 'Re-run query' })).toBeNull()
    api.setAuto.mockResolvedValue({ ...base })
    fireEvent.click(screen.getByRole('button', { name: 'Resume' }))
    await waitFor(() => expect(api.setAuto).toHaveBeenCalledWith('t-1', false))
  })

  it('hides every action from a reader who cannot change the task', () => {
    api.query = { ...base, mode: 'auto', auto_state: 'active' }
    render(<TaskQueryPanel taskId="t-1" writable={false} />)
    expect(screen.queryByRole('button')).toBeNull()
  })
})
