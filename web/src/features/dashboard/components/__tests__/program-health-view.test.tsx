import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

type Hook = { data?: unknown; error?: unknown; isLoading: boolean; mutate: () => void }
const idle: Hook = { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }
let summary: Hook
let rest: Hook
const executiveSpy = vi.fn()

vi.mock('../../hooks/use-ctem-dashboard', () => ({
  useExecutiveSummary: (...a: unknown[]) => {
    executiveSpy(...a)
    return summary
  },
  useMttrAnalytics: () => rest,
  useDataQuality: () => rest,
  useRiskTrend: () => rest,
  useValidationCoverage: () => rest,
}))
vi.mock('../program-metrics-section', () => ({ ProgramMetricsSection: () => null }))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: () => true }),
  Permission: { DashboardRead: 'dashboard:read' },
}))

import { ProgramHealthView } from '../program-health-view'

describe('ProgramHealthView', () => {
  beforeEach(() => {
    executiveSpy.mockClear()
    summary = { ...idle }
    rest = { ...idle }
  })

  it('sends the selected period (default 90 days) to the executive summary', () => {
    render(<ProgramHealthView />)
    expect(executiveSpy).toHaveBeenCalledWith('t1', 90)
  })

  it('shows the error state with retry when every source failed, not "no data yet"', () => {
    summary = { ...idle, error: new Error('boom') }
    rest = { ...idle, error: new Error('boom') }
    render(<ProgramHealthView />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
    expect(screen.queryByText(/no program data yet/i)).toBeNull()
  })

  it('does not print the internal provenance lines', () => {
    summary = {
      ...idle,
      data: {
        p0_open: 1,
        p0_resolved_period: 3,
        findings_total: 10,
        findings_resolved_period: 3,
        sla_compliance_pct: 80,
        regression_count: 0,
        regression_rate_pct: 5,
      },
    }
    render(<ProgramHealthView />)
    expect(screen.getAllByText(/P0 fixed in period/i).length).toBeGreaterThan(0)
    expect(screen.queryByText(/executive-summary/)).toBeNull()
    expect(screen.queryByText(/^(From|Source):/)).toBeNull()
  })
})
