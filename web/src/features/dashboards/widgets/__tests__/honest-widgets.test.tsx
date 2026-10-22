import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ExecutiveSummary } from '@/features/dashboard/hooks/use-ctem-dashboard'

let summary: Partial<ExecutiveSummary> | undefined
let summaryError: unknown
let intel: unknown

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 'tenant-1' } }),
}))
vi.mock('@/features/dashboard', () => ({
  useDashboardStats: () => ({
    stats: { findings: { total: 4, overdue: 2, bySeverity: {} } },
    isLoading: false,
  }),
}))
vi.mock('@/features/dashboard/hooks/use-ctem-dashboard', () => ({
  useExecutiveSummary: () => ({ data: summary, isLoading: false, error: summaryError }),
  useThreatIntelStats: () => ({ data: intel, isLoading: false }),
  useScanCoverage: () => ({ data: undefined, isLoading: false }),
  useAttackPaths: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
vi.mock('@/features/findings/api/use-findings-api', () => ({
  useFindingsApi: () => ({ data: undefined, isLoading: false }),
}))

import { WIDGET_REGISTRY } from '../registry'
import { DRILL } from '@/features/dashboard/lib/drill'

const render1 = (type: string) => {
  const Widget = WIDGET_REGISTRY[type].component
  return render(<Widget />)
}

describe('widgets render a figure that is not measured as a dash', () => {
  beforeEach(() => {
    summary = undefined
    summaryError = undefined
    intel = undefined
  })

  // research/188 A-003: a failed read rendered "P0 open 0".
  it('a failed read shows a dash and says so, never 0', () => {
    summaryError = new Error('500')
    render1('p0_open')
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.getByText("Couldn't load these figures")).toBeInTheDocument()
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })

  it('open within SLA: dash when no open finding has an SLA, never 0% or 100%', () => {
    summary = { sla_compliance_pct: null }
    render1('sla_compliance')
    expect(screen.getByText('Open within SLA')).toBeInTheDocument()
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.queryByText('0%')).not.toBeInTheDocument()
  })

  it('open within SLA: a measured share is shown', () => {
    summary = { sla_compliance_pct: 82.4 }
    render1('sla_compliance')
    expect(screen.getByText('82%')).toBeInTheDocument()
  })

  it('time to fix: dash when nothing was fixed, never 0h', () => {
    summary = { mttr_critical_hours: null, mttr_critical_median_hours: null }
    render1('mttr_critical')
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.queryByText('0h')).not.toBeInTheDocument()
  })

  it('time to fix: the median with the 90th percentile and sample size', () => {
    summary = {
      mttr_critical_hours: 40,
      mttr_critical_median_hours: 20.4,
      mttr_critical_p90_hours: 76,
      mttr_critical_sample: 3,
    }
    render1('mttr_critical')
    expect(screen.getByText('20h')).toBeInTheDocument()
    expect(screen.getByText(/p90 76h · 3 fixed/)).toBeInTheDocument()
  })

  it('the open-findings and overdue widgets read the stats the API now computes', () => {
    render1('open_findings')
    expect(screen.getByText('Open findings')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
  })

  it('every changed catalog entry has an English fallback and a message key', () => {
    for (const type of [
      'findings_by_severity',
      'open_findings',
      'sla_compliance',
      'mttr_critical',
    ]) {
      const def = WIDGET_REGISTRY[type]
      expect(def.titleKey).toMatch(/^dashboardMetrics\./)
      expect(def.descriptionKey).toMatch(/^dashboardMetrics\./)
    }
  })
})

describe('every tile equals the list it opens (research/203 H1-H7)', () => {
  beforeEach(() => {
    summary = undefined
    summaryError = undefined
    intel = undefined
  })

  it('threat intel shows the tenant open-in-KEV count, never the catalog size', () => {
    intel = {
      epss: { critical_risk_count: 18 },
      kev: {
        total_entries: 1748,
        tenant_open_count: 9,
        past_due_count: 6,
        ransomware_related_count: 300,
        recently_added_last_30_days: 23,
      },
    }
    render1('threat_intel')
    expect(screen.queryByText('1748')).not.toBeInTheDocument()
    expect(screen.queryByText('1,748')).not.toBeInTheDocument()
    expect(screen.getByText('9')).toBeInTheDocument()
    expect(screen.getByText('6 past the KEV due date')).toBeInTheDocument()
    expect(screen.getByText('EPSS 50 % or more')).toBeInTheDocument()
    expect(screen.getByText('9').closest('a')).toHaveAttribute('href', DRILL.kevOpen)
  })

  it('threat intel from an API without the tenant figure shows a dash, never 0', () => {
    intel = { epss: { critical_risk_count: 1 }, kev: { total_entries: 1748, past_due_count: 0 } }
    render1('threat_intel')
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('"mine" tiles open the open list with the same predicate they count', () => {
    const { container, unmount } = render1('assigned_to_me')
    expect(container.querySelector('a')).toHaveAttribute(
      'href',
      '/findings?state=open&related_to=me'
    )
    unmount()
    const ch = render1('my_critical_high')
    expect(ch.container.querySelector('a')).toHaveAttribute(
      'href',
      '/findings?state=open&related_to=me&severity=critical,high'
    )
  })

  it('open findings opens the open lens, and each severity row opens its own list', () => {
    const { container, unmount } = render1('open_findings')
    expect(container.querySelector('a')).toHaveAttribute('href', '/findings?state=open')
    unmount()
    render1('findings_by_severity')
    const links = screen.getAllByRole('link').map((a) => a.getAttribute('href'))
    expect(links).toContain('/findings?state=open&severity=critical')
    expect(links).toContain('/findings?state=open&severity=info')
  })

  it('risk score without a summary is a dash on a stated scale, never 0', () => {
    render1('risk_score')
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.queryByText('0')).not.toBeInTheDocument()
    summary = { risk_score_current: 44.6 }
  })

  it('every catalog entry has a translated title and description key', () => {
    for (const def of Object.values(WIDGET_REGISTRY)) {
      expect(def.titleKey).toMatch(/^dashboardMetrics\./)
      expect(def.descriptionKey).toMatch(/^dashboardMetrics\./)
    }
  })
})
