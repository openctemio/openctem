import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CtemLoop } from '../ctem-loop'
import { ExposureHero } from '../exposure-hero'
import { CtemMaturityCard } from '../ctem-maturity-card'
import { DRILL } from '../../../lib/drill'
import { ApiClientError } from '@/lib/api/error-handler'
import type { ExecutiveSummary } from '../../../hooks/use-ctem-dashboard'

vi.mock('next/dynamic', () => ({ default: () => () => null }))

// research/188 A-008/A-009: a figure opens exactly the list it counts, and a
// refusal is not shown as an empty or disabled feature.
const summary: ExecutiveSummary = {
  risk_score_current: 46,
  risk_score_change: 0,
  p0_open: 1,
  p0_resolved_period: 0,
  p1_open: 12,
  sla_compliance_pct: 52,
  sla_breached: 20,
  mttr_critical_hours: null,
  crown_jewels_at_risk: 3,
  findings_total: 47,
  findings_resolved_period: 5,
  top_risks: [],
}

function stageLink(name: string) {
  return screen.getByText(name).closest('a')
}

describe('CTEM loop drill-downs', () => {
  it('opens the counted lists, and Validate no longer opens Compensating controls', () => {
    render(
      <CtemLoop
        summary={summary}
        scanCoverage={{ coverage_percent: 0, never_scanned: 10, critical_uncovered: 0 }}
        validationCoverage={{ overall_pct: 0, validated: 0, total: 47 }}
      />
    )
    expect(stageLink('Prioritize')).toHaveAttribute('href', DRILL.p0Open)
    expect(stageLink('Validate')).toHaveAttribute('href', '/validation')
    expect(stageLink('Mobilize')).toHaveAttribute('href', DRILL.slaBreached)
    expect(document.querySelector('a[href="/controls"]')).toBeNull()
    expect(DRILL.p0Open).toBe('/findings?state=open&priority_class=P0')
    expect(DRILL.slaBreached).toBe('/findings?state=open&sla_status=overdue,exceeded')
  })

  it('the hero P0 number opens the open P0 list', () => {
    render(<ExposureHero summary={summary} trend={[]} kevChainCount={0} />)
    expect(screen.getByRole('link', { name: 'Open P0 findings: 1' })).toHaveAttribute(
      'href',
      DRILL.p0Open
    )
  })
})

describe('CTEM maturity card', () => {
  it('is left out for a viewer refused organization figures, not "no closed cycles"', () => {
    const { container } = render(
      <CtemMaturityCard error={new ApiClientError('forbidden', 'FORBIDDEN', 403)} />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('shows a failure with Retry', () => {
    render(
      <CtemMaturityCard
        error={new ApiClientError('boom', 'INTERNAL_ERROR', 500)}
        onRetry={vi.fn()}
      />
    )
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
    expect(screen.queryByText('No closed cycles yet')).toBeNull()
  })
})
