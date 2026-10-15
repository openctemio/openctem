import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ScoringChangeNote } from '../scoring-change-note'
import { scoringChangeDates, type RiskTrendPoint } from '../../../hooks/use-ctem-dashboard'

const base = {
  risk_score_avg: 0,
  findings_open: 0,
  sla_compliance_pct: 100,
  p0_open: 0,
  p1_open: 0,
  p2_open: 0,
  p3_open: 0,
}

const points: RiskTrendPoint[] = [
  { ...base, date: '2026-10-01' },
  {
    ...base,
    date: '2026-10-02',
    scoring_changes: [
      {
        date: '2026-10-02',
        kind: 'finding_priority',
        source: 'priority_rules',
        summary: 'Priority rule added',
      },
      {
        date: '2026-10-02',
        kind: 'asset_risk',
        source: 'risk_settings',
        summary: 'Risk scoring settings changed',
      },
    ],
  },
  { ...base, date: '2026-10-03' },
]

describe('scoring change markers', () => {
  it('marks only the dates of the chart kind', () => {
    expect(scoringChangeDates(points, 'finding_priority')).toEqual(['2026-10-02'])
    expect(scoringChangeDates([{ ...base, date: '2026-10-01' }], 'finding_priority')).toEqual([])
  })

  it('explains the marker in words, by source', () => {
    render(<ScoringChangeNote points={points} kind="finding_priority" />)
    expect(screen.getByText(/priority rules/)).toBeInTheDocument()
    expect(screen.getByText(/not directly comparable/)).toBeInTheDocument()
    expect(screen.queryByText(/risk scoring settings/)).not.toBeInTheDocument()
  })

  it('renders nothing without a change', () => {
    const { container } = render(<ScoringChangeNote points={[points[0]]} kind="finding_priority" />)
    expect(container).toBeEmptyDOMElement()
  })
})
