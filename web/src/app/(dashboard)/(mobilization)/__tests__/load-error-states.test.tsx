/**
 * Exceptions and Automations: a failed read says so with Retry. It used to
 * look like "no rules yet" / "no workflows yet".
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/exceptions',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'Acme', slug: 'acme', role: 'owner' } }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
  usePermissions: () => ({ can: () => true, canAny: () => true, canAll: () => true }),
}))
vi.mock('@/features/workflows/components/automation-workbench', () => ({
  AutomationWorkbench: () => null,
}))

const suppressions = vi.fn()
vi.mock('@/features/exceptions', async (orig) => ({
  ...(await orig<typeof import('@/features/exceptions')>()),
  useSuppressions: () => suppressions(),
  useApproveSuppression: () => ({ trigger: vi.fn(), isMutating: false }),
  useMarkSuppressionReviewed: () => ({ trigger: vi.fn(), isMutating: false }),
  useRejectSuppression: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteSuppression: () => ({ trigger: vi.fn(), isMutating: false }),
}))

const workflows = vi.fn()
const runs = vi.fn()
vi.mock('@/lib/api/workflow-hooks', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/workflow-hooks')>()),
  useWorkflows: () => workflows(),
  useWorkflowRuns: () => runs(),
  useTriggerWorkflow: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteWorkflow: () => ({ trigger: vi.fn(), isMutating: false }),
  useCreateWorkflow: () => ({ trigger: vi.fn(), isMutating: false }),
}))

import ExceptionsPage from '../exceptions/page'
import AutomationsPage from '../automations/page'

const apiError = new Error('boom: upstream timeout')
const idle = { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }

beforeEach(() => {
  suppressions.mockReset()
  workflows.mockReset()
  runs.mockReset()
})

describe('/exceptions', () => {
  it('shows an error state with Retry, not an empty table, when the read fails', () => {
    const retry = vi.fn()
    suppressions.mockReturnValue({ ...idle, error: apiError, mutate: retry })
    render(<ExceptionsPage />)
    expect(screen.getByText(/Failed to load suppression rules/i)).toBeInTheDocument()
    expect(screen.getByText(/Report this problem/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retry).toHaveBeenCalledTimes(1)
  })
})

describe('/automations', () => {
  it('shows an error state with Retry, not "No workflows yet", when the read fails', () => {
    workflows.mockReturnValue({ ...idle, error: apiError })
    runs.mockReturnValue({ ...idle, data: { data: [], total: 0 } })
    render(<AutomationsPage />)
    expect(screen.getByText(/Failed to load/i)).toBeInTheDocument()
    expect(screen.queryByText(/No workflows yet/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })
})
