import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import WorkflowsPage from '../page'

// The delete mutation is keyed by the workflow id: record the id it was built
// with when it fired. Before the confirm, the page triggered it in the same
// tick it set the id, so the hook still had no key and nothing was deleted.
const deleteCalls = vi.hoisted(() => [] as string[])
const hookId = vi.hoisted(() => ({ current: '' }))

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/workflows/components/automation-canvas', () => ({
  AutomationCanvas: () => null,
}))
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (_k: string, fallback: string) => [fallback, vi.fn()],
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
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
      ],
      total: 1,
    },
    isLoading: false,
    error: undefined,
  }),
  useWorkflowRuns: () => ({ data: { items: [], total: 0 }, isLoading: false }),
  useTriggerWorkflow: () => ({ trigger: vi.fn(), isMutating: false }),
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
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe('Automations delete', () => {
  it('asks first, then deletes the named workflow by its id', async () => {
    render(<WorkflowsPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Actions for Escalate criticals' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /Delete/ }))
    expect(deleteCalls).toHaveLength(0)
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete workflow "Escalate criticals"?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(deleteCalls).toEqual(['w1']))
    expect(hookId.current).toBe('')
  })
})
