/**
 * Creating a task from a query: the preview shows what the query selects in
 * the caller's access; matches other tasks hold are skipped unless moved
 * with a reason; too many matches block creation; auto mode shows its
 * guardrails and sends the cap. The request never carries a tenant or scope.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { CreateTaskFromQueryDialog } from '../components/create-task-from-query-dialog'
import type { QueryTaskPreview } from '../api/use-task-query'

const api = vi.hoisted(() => ({
  preview: vi.fn(),
  create: vi.fn(),
  explain: vi.fn(),
  push: vi.fn(),
  toast: vi.fn(),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: api.push }) }))
vi.mock('sonner', () => ({ toast: { success: api.toast, error: vi.fn() } }))
vi.mock('../api/use-owner-names', () => ({
  useOwnerNames: () => ({
    users: [{ id: 'u-1', name: 'Sam' }],
    groups: [{ id: 'g-1', name: 'Ops' }],
    user: (id?: string) => (id === 'u-1' ? 'Sam' : undefined),
    group: (id?: string) => (id === 'g-1' ? 'Ops' : undefined),
  }),
}))
vi.mock('../api/use-remediation-hub', () => ({ useRevalidateHub: () => vi.fn() }))
vi.mock('../api/use-task-query', async (orig) => {
  const real = await orig<typeof import('../api/use-task-query')>()
  return {
    ...real,
    taskQueryApi: {
      ...real.taskQueryApi,
      preview: api.preview,
      create: api.create,
      explain: api.explain,
    },
    useFindingQuerySchema: () => ({ data: { fields: [] } }),
  }
})

function preview(over: Partial<QueryTaskPreview> = {}): QueryTaskPreview {
  return {
    query: 'findings where severity = critical',
    query_version: 2,
    description: 'critical findings',
    scope_kind: 'data_scope',
    scope_rules: [],
    total: 3,
    too_many: false,
    max: 1000,
    claimable: 2,
    stats: {
      severity: [{ key: 'critical', name: 'critical', count: 3 }],
      assets: [{ key: 'a-1', name: 'api.example.com', count: 3 }],
      owners: [{ key: 'u:u-1', name: 'Sam', count: 3, user_id: 'u-1' }],
      sample: [
        {
          finding_id: 'f-1',
          title: '<b>TLS 1.0</b>',
          severity: 'critical',
          status: 'new',
          asset_name: 'api.example.com',
        },
      ],
      earliest_deadline: '2026-11-01T00:00:00Z',
    },
    conflicts: [
      {
        finding_id: 'f-3',
        finding_title: 'Weak cipher',
        task_id: 't-2',
        task_title: null,
        assignee_user_id: null,
        assignee_group_id: null,
        can_move: false,
      },
    ],
    suggested_assignee: { user_id: 'u-1' },
    ...over,
  }
}

async function openAndPreview(p: QueryTaskPreview) {
  api.preview.mockResolvedValue(p)
  render(
    <CreateTaskFromQueryDialog
      open
      onOpenChange={vi.fn()}
      initialQuery="findings where severity = critical"
    />
  )
  fireEvent.click(screen.getByRole('button', { name: 'Preview' }))
  return screen.findByTestId('query-preview')
}

describe('CreateTaskFromQueryDialog', () => {
  beforeEach(() => {
    api.preview.mockReset()
    api.create.mockReset()
    api.explain.mockReset().mockResolvedValue({ query: '', description: 'ok', entity: 'findings' })
  })

  it('previews counts, the scope, the suggested owner and plain-text samples', async () => {
    const panel = await openAndPreview(preview())
    expect(api.preview).toHaveBeenCalledWith('findings where severity = critical')
    expect(panel).toHaveTextContent('3 matching findings')
    expect(panel).toHaveTextContent('2 can join; 1 already belong to other tasks')
    expect(panel).toHaveTextContent('Counted over the findings in your data scope.')
    expect(panel).toHaveTextContent('Sam')
    // Scanner text is shown as text, never as markup.
    expect(panel).toHaveTextContent('<b>TLS 1.0</b>')
    expect(panel.querySelector('b')).toBeNull()
    // A task the caller cannot read is never named.
    expect(screen.getByTestId('claim-conflict-step')).toHaveTextContent('In a task you cannot see')
  })

  it('creates a snapshot task skipping held findings, with the suggested owner', async () => {
    await openAndPreview(preview())
    api.create.mockResolvedValue({
      task: { id: 't-9', title: 'Fix' },
      added: 2,
      moved: 0,
      skipped: 1,
    })
    fireEvent.click(screen.getByRole('button', { name: 'Create task' }))
    await waitFor(() => expect(api.create).toHaveBeenCalled())
    const body = api.create.mock.calls[0][0]
    expect(body).toMatchObject({
      query: 'findings where severity = critical',
      mode: 'snapshot',
      assignee_user_id: 'u-1',
      conflicts: { skip: true },
    })
    expect(body).not.toHaveProperty('tenant_id')
    expect(body).not.toHaveProperty('cap')
    await waitFor(() => expect(api.push).toHaveBeenCalledWith('/remediation/tasks/t-9'))
  })

  it('blocks creation above the cap and explains how to narrow', async () => {
    const panel = await openAndPreview(
      preview({ too_many: true, total: 1500, stats: undefined, conflicts: [] })
    )
    expect(panel).toHaveTextContent('More than 1000 findings match')
    expect(screen.getByRole('button', { name: 'Create task' })).toBeDisabled()
  })

  it('auto mode shows the guardrails and sends the cap', async () => {
    await openAndPreview(preview({ conflicts: [], claimable: 3 }))
    fireEvent.click(screen.getByRole('radio', { name: /Auto include/ }))
    expect(
      screen.getByText(/Only findings that are not already in another open task/)
    ).toBeInTheDocument()
    expect(screen.getByText(/stops by itself if you leave the organization/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Most findings in this task'), {
      target: { value: '200' },
    })
    api.create.mockResolvedValue({
      task: { id: 't-9', title: 'Fix' },
      added: 3,
      moved: 0,
      skipped: 0,
    })
    fireEvent.click(screen.getByRole('button', { name: 'Create task' }))
    await waitFor(() => expect(api.create).toHaveBeenCalled())
    expect(api.create.mock.calls[0][0]).toMatchObject({ mode: 'auto', cap: 200 })
    expect(api.create.mock.calls[0][0]).not.toHaveProperty('conflicts')
  })

  it('asks for a new preview after the query changes', async () => {
    await openAndPreview(preview())
    fireEvent.change(screen.getByLabelText('Query'), {
      target: { value: 'findings where severity = high' },
    })
    expect(
      screen.getByText('The query changed: preview again before creating.')
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create task' })).toBeDisabled()
  })
})
