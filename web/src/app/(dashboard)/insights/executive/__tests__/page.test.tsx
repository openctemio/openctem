import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'

type Hook = { data?: unknown; error?: unknown; isLoading: boolean; mutate: () => void }
const idle: Hook = { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }
let summary: Hook
let mttr: Hook
let process: Hook
const executiveSpy = vi.fn()

vi.mock('@/features/dashboard/hooks/use-ctem-dashboard', () => ({
  MTTR_WINDOW_DAYS: 90,
  useExecutiveSummary: (...a: unknown[]) => {
    executiveSpy(...a)
    return summary
  },
  useMttrAnalytics: () => mttr,
  useProcessMetrics: () => process,
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

import ExecutiveSummaryPage from '../page'

const baseSummary = {
  risk_score_current: 40,
  risk_score_change: 0,
  p0_open: 1,
  p0_resolved_period: 0,
  p1_open: 2,
  p1_resolved_period: 0,
  sla_compliance_pct: 90,
  sla_breached: 1,
  mttr_critical_hours: 10,
  mttr_critical_median_hours: 8,
  mttr_critical_sample: 6,
  mttr_high_hours: 20,
  crown_jewels_at_risk: 0,
  findings_total: 20,
  findings_resolved_period: 4,
  top_risks: [],
}

describe('ExecutiveSummaryPage', () => {
  beforeEach(() => {
    executiveSpy.mockClear()
    summary = { ...idle, data: baseSummary }
    mttr = { ...idle }
    process = { ...idle }
  })

  it('sends the selected period (default 30 days) to the summary', () => {
    render(<ExecutiveSummaryPage />)
    expect(executiveSpy).toHaveBeenCalledWith('t1', 30)
  })

  it('labels the fixed-window sections', () => {
    process = {
      ...idle,
      data: {
        approval_avg_hours: 1,
        approval_count: 2,
        stale_assets: 3,
        stale_assets_pct: 4,
        findings_without_owner: 5,
        avg_time_to_assign_hours: 6,
      },
    }
    render(<ExecutiveSummaryPage />)
    expect(screen.getByText('Last 90 days')).toBeInTheDocument()
  })

  it('lists every severity in the by-severity card and sorts priorities P0 to P3', () => {
    mttr = {
      ...idle,
      data: {
        by_severity: { critical: 30, high: 40 },
        by_priority_class: { P3: 4, P0: 1, P2: 3, P1: 2 },
        overall_hours: 35,
        sample_size: 9,
      },
    }
    render(<ExecutiveSummaryPage />)
    const card = screen
      .getByText('MTTR by severity')
      .closest('[data-slot="card"], div.rounded-xl, div')!
    const sev = card.parentElement!.parentElement!
    expect(sev.textContent).toMatch(/critical/i)
    const prio = screen.getByText('MTTR by priority class').closest('div')!.parentElement!
      .parentElement!
    const order = within(prio)
      .getAllByText(/^P[0-3]$/)
      .map((e) => e.textContent)
    expect(order).toEqual(['P0', 'P1', 'P2', 'P3'])
  })

  it('keys top risks by finding so a shared title does not collide', () => {
    const risk = (id: string) => ({
      title: 'CVE-1',
      severity: 'high',
      priority_class: 'P1',
      asset_name: 'a',
      is_in_kev: false,
      finding_id: id,
    })
    summary = { ...idle, data: { ...baseSummary, top_risks: [risk('f1'), risk('f2')] } }
    const spy = vi.spyOn(console, 'error')
    render(<ExecutiveSummaryPage />)
    expect(screen.getAllByText('CVE-1')).toHaveLength(2)
    expect(spy.mock.calls.flat().join(' ')).not.toMatch(/same key/)
    spy.mockRestore()
  })

  it('shows the error state with retry when the summary failed', () => {
    summary = { ...idle, error: new Error('x') }
    render(<ExecutiveSummaryPage />)
    expect(screen.getAllByRole('alert').length).toBeGreaterThan(0)
  })
})
