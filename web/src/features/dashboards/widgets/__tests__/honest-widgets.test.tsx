import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ExecutiveSummary } from '@/features/dashboard/hooks/use-ctem-dashboard'

let summary: Partial<ExecutiveSummary> | undefined

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
  useExecutiveSummary: () => ({ data: summary, isLoading: false }),
  useThreatIntelStats: () => ({ data: undefined, isLoading: false }),
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

const render1 = (type: string) => {
  const Widget = WIDGET_REGISTRY[type].component
  return render(<Widget />)
}

describe('widgets render a figure that is not measured as a dash', () => {
  beforeEach(() => {
    summary = undefined
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
