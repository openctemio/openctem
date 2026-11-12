/**
 * Compliance: a failed read says so with Retry. A failed frameworks read used
 * to render "No frameworks yet", and failed totals rendered as zeros.
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
  usePathname: () => '/compliance',
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

const frameworks = vi.fn()
const stats = vi.fn()
const idleControls = { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }
vi.mock('@/features/compliance/api/use-compliance-api', async (orig) => ({
  ...(await orig<typeof import('@/features/compliance/api/use-compliance-api')>()),
  useFrameworks: () => frameworks(),
  useComplianceStats: () => stats(),
  useFrameworkControls: () => idleControls,
  useAssessments: () => idleControls,
  useUpdateAssessment: () => ({ trigger: vi.fn(), isMutating: false }),
}))

import CompliancePage from '../compliance/page'

const apiError = new Error('boom: upstream timeout')
const idle = { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }

beforeEach(() => {
  frameworks.mockReset()
  stats.mockReset()
})

describe('/compliance', () => {
  it('shows a failed frameworks read as an error with Retry, not "No frameworks yet"', () => {
    const retry = vi.fn()
    frameworks.mockReturnValue({ ...idle, error: apiError, mutate: retry })
    stats.mockReturnValue({ ...idle, data: { total_frameworks: 1, total_controls: 2 } })
    render(<CompliancePage />)
    expect(screen.getByText(/Failed to load frameworks/i)).toBeInTheDocument()
    expect(screen.queryByText(/No frameworks yet/i)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retry).toHaveBeenCalledTimes(1)
  })

  it('shows failed totals as an error with Retry, not as zeros', () => {
    const retry = vi.fn()
    frameworks.mockReturnValue({ ...idle, data: { data: [], total: 0 } })
    stats.mockReturnValue({ ...idle, error: apiError, mutate: retry })
    render(<CompliancePage />)
    expect(screen.getByText(/Failed to load compliance summary/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retry).toHaveBeenCalledTimes(1)
  })
})
