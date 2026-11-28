/**
 * MaturityBreakdownCard — renders the overall score and every weighted
 * component transparently (score, weight, contribution, detail).
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MaturityBreakdownCard, scoreTone } from '../maturity-breakdown'
import type { MaturityBreakdown } from '../../api/use-ctem-maturity'
import { I18nProvider } from '@/context/i18n-provider'

const breakdown: MaturityBreakdown = {
  score: 72.5,
  cycles_analyzed: 3,
  ctem_stage_coverage: {
    scoping: true,
    discovery: true,
    prioritization: true,
    validation: true,
    mobilization: false,
    covered_count: 4,
  },
  components: [
    {
      name: 'validation_coverage',
      raw_value: 80,
      score: 80,
      weight: 0.3,
      contribution: 24,
      detail: 'share of closed findings with validation evidence (%)',
    },
    {
      name: 'resolution_throughput',
      raw_value: 0.9,
      score: 90,
      weight: 0.25,
      contribution: 22.5,
      detail: 'findings_resolved / findings_opened this cycle',
      detail_code: 'resolution_ratio',
    },
  ],
}

describe('MaturityBreakdownCard', () => {
  it('renders the rounded overall score', () => {
    render(<MaturityBreakdownCard maturity={breakdown} />)
    expect(screen.getByText('73')).toBeInTheDocument()
  })

  it('renders each component with its label, weight and contribution', () => {
    render(<MaturityBreakdownCard maturity={breakdown} />)
    expect(screen.getByText('Validation coverage')).toBeInTheDocument()
    expect(screen.getByText('Resolution throughput')).toBeInTheDocument()
    // weight rendered as a percentage
    expect(screen.getByText('30%')).toBeInTheDocument()
    expect(screen.getByText('25%')).toBeInTheDocument()
    // contribution rendered with a leading +
    expect(screen.getByText('+24')).toBeInTheDocument()
    expect(screen.getByText('+22.5')).toBeInTheDocument()
    // the detail reads from its code in plain words, never as metric keys
    expect(
      screen.getByText('Findings resolved this cycle compared with findings opened')
    ).toBeInTheDocument()
    expect(screen.queryByText(/findings_resolved/)).toBeNull()
    // a detail without a code keeps the server's sentence
    expect(
      screen.getByText('share of closed findings with validation evidence (%)')
    ).toBeInTheDocument()
    expect(screen.queryByText(/Σ/)).toBeNull()
  })

  it('does not throw when components is null (no cycles analyzed)', () => {
    const empty: MaturityBreakdown = { ...breakdown, score: 0, components: null }
    render(<MaturityBreakdownCard maturity={empty} />)
    expect(screen.getByText('0')).toBeInTheDocument()
  })

  it('shows a dash for raw values and contributions on a single cycle', () => {
    render(<MaturityBreakdownCard maturity={{ ...breakdown, cycles_analyzed: 1 }} />)
    expect(screen.queryByText('+24')).toBeNull()
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(4)
  })

  it('words the details and the subtitle in Vietnamese', () => {
    render(
      <I18nProvider locale="vi">
        <MaturityBreakdownCard maturity={breakdown} />
      </I18nProvider>
    )
    expect(
      screen.getByText('Số phát hiện đã xử lý trong chu kỳ so với số phát hiện mới mở')
    ).toBeInTheDocument()
    expect(screen.queryByText(/this cycle|Σ/)).toBeNull()
  })

  it('scoreTone maps score bands to accents', () => {
    expect(scoreTone(90)).toBe('text-success')
    expect(scoreTone(60)).toBe('text-warning')
    expect(scoreTone(20)).toBe('text-destructive')
  })
})
