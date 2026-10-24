import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import WorkflowsPage from '../page'

// The delete mutation is keyed by the workflow id: record the id it was built
// with when it fired. Before the confirm, the page triggered it in the same
// tick it set the id, so the hook still had no key and nothing was deleted.
const deleteCalls = vi.hoisted(() => [] as string[])
const hookId = vi.hoisted(() => ({ current: '' }))
const triggerMock = vi.hoisted(() => vi.fn())
const putCalls = vi.hoisted(() => [] as string[])

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/workflows/components/automation-workbench', () => ({
  AutomationWorkbench: () => null,
}))
vi.mock('@/features/workflows/components/automation-run-sheet', () => ({
  AutomationRunSheet: () => null,
  useRunStatusLabel: () => (s: string) => s,
}))
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (_k: string, fallback: string) => [fallback, vi.fn()],
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useHasPermission: () => true,
}))
vi.mock('@/lib/api/workflow-hooks', () => ({
  useWorkflows: () => ({
    data: {
      items: [
        {
          id: 'w1',
          tenant_id: 't1',
          name: 'Escalate criticals',
          is_active: true,
          total_runs: 0,
          successful_runs: 0,
          failed_runs: 0,
          created_at: '2026-10-01T00:00:00Z',
          updated_at: '2026-10-01T00:00:00Z',
        },
        {
          id: 'w2',
          tenant_id: 't1',
          name: 'Idle flow',
          is_active: false,
          total_runs: 0,
          successful_runs: 0,
          failed_runs: 0,
          created_at: '2026-10-01T00:00:00Z',
          updated_at: '2026-10-01T00:00:00Z',
        },
      ],
      total: 2,
    },
    isLoading: false,
    error: undefined,
  }),
  useWorkflowRuns: () => ({ data: { items: [], total: 0 }, isLoading: false }),
  useTriggerWorkflow: () => ({ trigger: triggerMock, isMutating: false }),
  useCreateWorkflow: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteWorkflow: (id: string) => {
    hookId.current = id
    return {
      trigger: () => {
        deleteCalls.push(id)
        return id ? Promise.resolve() : Promise.reject(new Error('missing key'))
      },
      isMutating: false,
    }
  },
  invalidateWorkflowsCache: vi.fn(),
  invalidateWorkflowRunsCache: vi.fn(),
}))
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  csrfFetch: (url: string, init: { body: string }) => {
    putCalls.push(`${url} ${init.body}`)
    return Promise.resolve({ ok: true })
  },
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

async function openRowMenu() {
  await userEvent.click(screen.getByRole('button', { name: 'Actions for Escalate criticals' }))
}

describe('Automations delete', () => {
  it('asks first, then deletes only after the workflow name is typed', async () => {
    render(<WorkflowsPage />)
    await openRowMenu()
    await userEvent.click(await screen.findByRole('menuitem', { name: /Delete/ }))
    expect(deleteCalls).toHaveLength(0)
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete workflow "Escalate criticals"?')
    const confirm = within(dialog).getByRole('button', { name: 'Delete workflow' })
    expect(confirm).toBeDisabled()
    await userEvent.type(within(dialog).getByRole('textbox'), 'Escalate criticals')
    await userEvent.click(confirm)
    await waitFor(() => expect(deleteCalls).toEqual(['w1']))
    expect(hookId.current).toBe('')
  })
})

describe('Automations run and activate', () => {
  it('Run now asks first and runs the workflow only after Run workflow', async () => {
    triggerMock.mockReset().mockResolvedValue({})
    render(<WorkflowsPage />)
    await openRowMenu()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Run now' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Run the workflow "Escalate criticals" now?')
    expect(triggerMock).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Run workflow' }))
    await waitFor(() => expect(triggerMock).toHaveBeenCalledWith({ trigger_type: 'manual' }))
  })

  it('Cancel on the run question runs nothing', async () => {
    triggerMock.mockReset()
    render(<WorkflowsPage />)
    await openRowMenu()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Run now' }))
    await userEvent.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Cancel' })
    )
    expect(triggerMock).not.toHaveBeenCalled()
  })

  it('switching a workflow off is one click, no dialog', async () => {
    putCalls.length = 0
    render(<WorkflowsPage />)
    await userEvent.click(screen.getByRole('switch', { name: 'Deactivate workflow' }))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    await waitFor(() => expect(putCalls).toHaveLength(1))
    expect(putCalls[0]).toContain('"is_active":false')
  })

  it('switching a workflow on asks first and activates only after Activate workflow', async () => {
    putCalls.length = 0
    render(<WorkflowsPage />)
    await userEvent.click(screen.getByRole('switch', { name: 'Activate workflow' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Activate the workflow "Idle flow"?')
    expect(putCalls).toHaveLength(0)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Activate workflow' }))
    await waitFor(() => expect(putCalls).toHaveLength(1))
    expect(putCalls[0]).toContain('/api/v1/workflows/w2')
    expect(putCalls[0]).toContain('"is_active":true')
  })
})
