import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

type Hook = { data?: unknown; error?: unknown; isLoading: boolean; mutate: () => void }
const idle: Hook = { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }
let summary: Hook
let rest: Hook
let mttrHook: Hook | undefined
let qualityHook: Hook | undefined
const executiveSpy = vi.fn()

vi.mock('../../hooks/use-ctem-dashboard', () => ({
  useExecutiveSummary: (...a: unknown[]) => {
    executiveSpy(...a)
    return summary
  },
  useMttrAnalytics: () => mttrHook ?? rest,
  useDataQuality: () => qualityHook ?? rest,
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
    mttrHook = undefined
    qualityHook = undefined
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
    expect(screen.getByText('P0 fixed within target')).toBeInTheDocument()
    expect(screen.queryByText(/executive-summary/)).toBeNull()
    expect(screen.queryByText(/^(From|Source):/)).toBeNull()
  })

  const data = {
    p0_open: 1,
    p0_resolved_period: 6,
    findings_total: 40,
    findings_resolved_period: 9,
    sla_compliance_pct: 60,
    sla_breached: 12,
    regression_count: 2,
    regression_rate_pct: 5,
  }

  it('answers one question first: the one big number, the counts and the target', () => {
    summary = { ...idle, data }
    qualityHook = { ...idle, data: { asset_ownership_pct: 40 } }
    mttrHook = { ...idle, data: { by_priority_class: { P0: 24 * 20 } } }
    const { container } = render(<ProgramHealthView />)
    const answer = container.querySelector('[data-slot="overview-answer"]') as HTMLElement
    expect(answer.querySelector('[data-slot="overview-answer-value"]')?.textContent).toBe('86%')
    expect(answer.textContent).toContain('6 of 7 P0 findings were fixed in the last 90 days.')
    expect(answer.textContent).toContain('more than 90%')
    // The only text-4xl on the page.
    expect(container.querySelectorAll('.text-4xl')).toHaveLength(1)
  })

  it('says not measured with the reason when no P0 finding exists', () => {
    summary = { ...idle, data: { ...data, p0_open: 0, p0_resolved_period: 0 } }
    const { container } = render(<ProgramHealthView />)
    const answer = container.querySelector('[data-slot="overview-answer"]') as HTMLElement
    expect(answer.getAttribute('data-state')).toBe('not-measured')
    expect(answer.textContent).toContain('Not measured')
    expect(answer.textContent).toContain('nothing to divide')
    expect(answer.querySelector('.text-4xl')).toBeNull()
  })

  it('lists where to act as links to existing filtered lists, worst first', () => {
    summary = { ...idle, data: { ...data, p0_open: 5, p0_resolved_period: 1 } }
    qualityHook = { ...idle, data: { asset_ownership_pct: 40 } }
    mttrHook = { ...idle, data: { by_priority_class: { P0: 24 * 20 } } }
    const { container } = render(<ProgramHealthView />)
    const rows = Array.from(
      container.querySelectorAll('[data-slot="overview-act-row"]')
    ) as HTMLAnchorElement[]
    const hrefs = rows.map((r) => r.getAttribute('href'))
    expect(rows.length).toBeLessThanOrEqual(5)
    expect(hrefs).toContain('/findings?state=open&priority_class=P0')
    expect(hrefs).toContain('/findings?state=open&sla_status=overdue,exceeded')
    expect(hrefs).toContain('/assets/attention/no-owner')
    expect(screen.getAllByText('Off track').length).toBeGreaterThan(0)
  })

  it('renders one strip of at most five tiles, each a link or not measured', () => {
    summary = { ...idle, data }
    qualityHook = { ...idle, data: { asset_ownership_pct: 40 } }
    mttrHook = { ...idle, data: { by_priority_class: { P0: 24 * 3 } } }
    const { container } = render(<ProgramHealthView />)
    const strips = container.querySelectorAll('[data-slot="metric-strip"]')
    expect(strips).toHaveLength(1)
    const tiles = Array.from(strips[0].querySelectorAll('[data-slot="metric-tile"]'))
    expect(tiles.length).toBeLessThanOrEqual(5)
    for (const tile of tiles) {
      const linked = tile.tagName === 'A' && !!tile.getAttribute('href')
      const unmeasured = tile.getAttribute('data-state') === 'not-measured'
      expect(linked || unmeasured).toBe(true)
    }
    // Validation has no data in this fixture: its tile is not measured, not a link.
    expect(
      container.querySelector('[data-slot="metric-tile"][data-state="not-measured"]')
    ).toBeTruthy()
  })

  it('has no card per metric and no status pill on tiles', () => {
    summary = { ...idle, data }
    const { container } = render(<ProgramHealthView />)
    expect(container.querySelectorAll('[data-slot="card"]')).toHaveLength(0)
    expect(screen.queryByText('On track')).toBeNull()
  })
})
