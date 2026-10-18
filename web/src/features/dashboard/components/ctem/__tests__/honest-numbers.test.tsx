import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { ExposureHero } from '../exposure-hero'
import { CtemLoop } from '../ctem-loop'
import { CoverageHygiene } from '../coverage-hygiene'
import type { ExecutiveSummary, ThreatIntelStats } from '../../../hooks/use-ctem-dashboard'

vi.mock('@/components/charts', () => {
  const Passthrough = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>
  const Null = () => null
  return {
    LineChart: Passthrough,
    AreaChart: Passthrough,
    BarChart: Passthrough,
    PieChart: Passthrough,
    ResponsiveContainer: Passthrough,
    Line: Null,
    Area: Null,
    Bar: Null,
    Pie: Null,
    Cell: Null,
    XAxis: Null,
    YAxis: Null,
    Tooltip: Null,
    Legend: Null,
    CartesianGrid: Null,
  }
})

// No open finding has an SLA and nothing was fixed: both figures are not
// measured (null), never a compliant 100% or a 0 h fix time.
const notMeasured: ExecutiveSummary = {
  risk_score_current: 10,
  risk_score_change: 0,
  p0_open: 0,
  p0_resolved_period: 0,
  p1_open: 0,
  sla_compliance_pct: null,
  sla_breached: 0,
  mttr_critical_hours: null,
  crown_jewels_at_risk: 0,
  findings_total: 0,
  findings_resolved_period: 0,
  top_risks: [],
}

const intel = {
  epss: { critical_risk_count: 5 },
  kev: {
    total_entries: 1662,
    tenant_open_count: 12,
    past_due_count: 3,
    ransomware_related_count: 339,
    recently_added_last_30_days: 25,
  },
} as ThreatIntelStats

describe('not-measured figures render as a dash', () => {
  it('the exposure hero shows a dash for the SLA share, not 0% or 100%', () => {
    render(<ExposureHero summary={notMeasured} kevChainCount={0} />)
    const label = screen.getByText(/Within SLA/i)
    expect(within(label).getByText('—')).toBeInTheDocument()
    expect(screen.queryByText('0%')).not.toBeInTheDocument()
    expect(screen.queryByText('100%')).not.toBeInTheDocument()
  })

  it('the exposure hero still shows a measured share', () => {
    render(
      <ExposureHero summary={{ ...notMeasured, sla_compliance_pct: 82.4 }} kevChainCount={0} />
    )
    expect(screen.getByText('82%')).toBeInTheDocument()
  })

  it('the CTEM loop shows a dash and no "on track" flag when no SLA is measurable', () => {
    render(<CtemLoop summary={notMeasured} threatIntel={intel} />)
    expect(screen.getByText(/open within SLA · 0 breached/i)).toBeInTheDocument()
    expect(screen.queryByText(/on track/i)).not.toBeInTheDocument()
    const stage = screen.getByText('Mobilize').closest('a') as HTMLElement
    expect(within(stage).getByText('—')).toBeInTheDocument()
  })

  it('the CTEM loop shows the tenant open KEV findings, not the catalog size', () => {
    render(<CtemLoop summary={notMeasured} threatIntel={intel} />)
    expect(screen.getByText(/12 open findings in KEV/i)).toBeInTheDocument()
    expect(screen.queryByText(/1,662/)).not.toBeInTheDocument()
    expect(screen.queryByText(/in catalog/i)).not.toBeInTheDocument()
  })

  it('the loop labels its crown jewel count by what it counts', () => {
    render(<CtemLoop summary={{ ...notMeasured, crown_jewels_at_risk: 2 }} threatIntel={intel} />)
    expect(screen.getByText(/crown jewels with open findings/i)).toBeInTheDocument()
    expect(screen.queryByText(/on an attack path/i)).not.toBeInTheDocument()
  })

  it('the coverage card names the scan row by what it measures and dashes a null SLA', () => {
    render(
      <CoverageHygiene
        scan={{ coverage_percent: 80, never_scanned: 1, critical_uncovered: 0 }}
        validation={{ overall_pct: 50, validated: 1, total: 2 }}
        slaPct={null}
      />
    )
    expect(screen.getByText('Connector dispatch freshness')).toBeInTheDocument()
    const sla = screen.getByText('Open within SLA').parentElement as HTMLElement
    expect(within(sla).getByText('—')).toBeInTheDocument()
  })
})
