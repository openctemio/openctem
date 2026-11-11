/**
 * Scans and Workflows: a failed read says so with Retry. It used to render the
 * empty list or zeros, which reads as "no scans yet".
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
  usePathname: () => '/scans',
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

vi.mock('@/features/scans/components/scans-section-tabs', () => ({
  ScansPageHeader: ({ title, children }: { title: string; children?: React.ReactNode }) => (
    <header>
      <h1>{title}</h1>
      {children}
    </header>
  ),
  ScansSectionTabs: () => null,
  ScanCreateActions: () => null,
}))

const workflows = vi.fn()
const configs = vi.fn()
const configStats = vi.fn()
vi.mock('@/lib/api/scan-hooks', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/scan-hooks')>()),
  useScanConfigs: () => configs(),
  useScanConfigStats: () => configStats(),
  useBulkActivateScanConfigs: () => ({ trigger: vi.fn(), isMutating: false }),
  useBulkPauseScanConfigs: () => ({ trigger: vi.fn(), isMutating: false }),
  useBulkDisableScanConfigs: () => ({ trigger: vi.fn(), isMutating: false }),
  useBulkDeleteScanConfigs: () => ({ trigger: vi.fn(), isMutating: false }),
}))
const invalidate = vi.fn()
vi.mock('@/lib/api', async (orig) => ({
  ...(await orig<typeof import('@/lib/api')>()),
  useScanWorkflows: () => workflows(),
  invalidateAllScanWorkflowCaches: () => invalidate(),
}))

import WorkflowsPage from '../scans/workflows/page'
import ScansPage from '../scans/page'

const apiError = new Error('boom: upstream timeout')

beforeEach(() => {
  workflows.mockReset()
  configs.mockReset()
  configStats.mockReset()
  invalidate.mockReset()
})

describe('/scans/workflows', () => {
  it('shows an error state with Retry, not the empty list, when the read fails', () => {
    workflows.mockReturnValue({ data: undefined, error: apiError, isLoading: false })
    render(<WorkflowsPage />)
    expect(screen.getByText(/Failed to load workflows/i)).toBeInTheDocument()
    expect(screen.getByText(/boom: upstream timeout/)).toBeInTheDocument()
    // The shared error state also offers the diagnostics.
    expect(screen.getByText(/Report this problem/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(invalidate).toHaveBeenCalledTimes(1)
  })
})

describe('/scans', () => {
  const idle = { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }

  it('shows the failed list read as an error with Retry, not an empty list', () => {
    const retry = vi.fn()
    configs.mockReturnValue({ ...idle, error: apiError, mutate: retry })
    configStats.mockReturnValue({ ...idle, data: { total: 3, active: 1, paused: 1, disabled: 1 } })
    render(<ScansPage />)
    expect(screen.getByText(/Failed to load scans/i)).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: /retry/i })[0])
    expect(retry).toHaveBeenCalledTimes(1)
  })

  it('shows failed counts as an error with Retry, not as zeros', () => {
    const retryStats = vi.fn()
    configs.mockReturnValue({ ...idle, data: { data: [], total: 0 } })
    configStats.mockReturnValue({ ...idle, error: apiError, mutate: retryStats })
    render(<ScansPage />)
    expect(screen.getByText(/Failed to load scan counts/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retryStats).toHaveBeenCalledTimes(1)
  })
})
