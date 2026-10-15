/**
 * RiskScoreBadge Component Tests
 *
 * Tests that RiskScoreBadge renders correct labels using thresholds from context.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import * as React from 'react'
import type { RiskLevelThresholds } from '../types/common.types'

// ============================================
// MOCKS
// ============================================

// Mock the risk-scoring-provider to return custom thresholds
const mockThresholds: RiskLevelThresholds = {
  critical_min: 90,
  high_min: 70,
  medium_min: 50,
  low_min: 30,
}

vi.mock('@/context/risk-scoring-provider', () => ({
  useRiskThresholds: vi.fn(() => mockThresholds),
  RiskScoringProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement('div', null, children),
}))

// Mock tooltip to simplify rendering
vi.mock('@/components/ui/tooltip', () => ({
  Tooltip: ({ children }: { children: React.ReactNode }) =>
    React.createElement('div', null, children),
  TooltipContent: ({ children }: { children: React.ReactNode }) =>
    React.createElement('div', null, children),
  TooltipProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement('div', null, children),
  TooltipTrigger: (() => {
    const Trigger = React.forwardRef<
      HTMLDivElement,
      { children: React.ReactNode; asChild?: boolean }
    >(({ children, ...props }, ref) => React.createElement('div', { ...props, ref }, children))
    Trigger.displayName = 'TooltipTrigger'
    return Trigger
  })(),
}))

// ============================================
// TESTS
// ============================================

describe('RiskScoreBadge', () => {
  it('renders Critical label for score >= custom critical threshold (90)', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={95} />)
    expect(screen.getByText('95 - Critical')).toBeInTheDocument()
  })

  it('renders High label for score between custom high and critical thresholds', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={75} />)
    expect(screen.getByText('75 - High')).toBeInTheDocument()
  })

  it('renders Medium label for score between custom medium and high thresholds', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={55} />)
    expect(screen.getByText('55 - Medium')).toBeInTheDocument()
  })

  it('renders Low label for score between custom low and medium thresholds', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={35} />)
    expect(screen.getByText('35 - Low')).toBeInTheDocument()
  })

  it('renders Minimal label for score below custom low threshold', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={15} />)
    expect(screen.getByText('15 - Minimal')).toBeInTheDocument()
  })

  it('renders only label when showScore is false', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={95} showScore={false} />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(screen.queryByText('95')).not.toBeInTheDocument()
  })

  // With custom thresholds (critical=90), score 85 should be High, not Critical
  it('respects custom thresholds — 85 is High with critical_min=90', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={85} />)
    expect(screen.getByText('85 - High')).toBeInTheDocument()
  })
})

describe('RiskScoreMeter', () => {
  it('renders score value', async () => {
    const { RiskScoreMeter } = await import('../components/risk-score-badge')
    render(<RiskScoreMeter score={65} showTooltip={false} />)
    expect(screen.getByText('65')).toBeInTheDocument()
  })
})

describe('RiskScoreGauge', () => {
  it('renders score and label', async () => {
    const { RiskScoreGauge } = await import('../components/risk-score-badge')
    render(<RiskScoreGauge score={92} />)
    expect(screen.getByText('92')).toBeInTheDocument()
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })
})

describe('RiskScoreBadge freshness', () => {
  it('shows 0 as no open risk, not Info', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={0} />)
    expect(screen.getByText('0 - No open risk')).toBeInTheDocument()
  })

  it('never shows a fake 0 for an asset that was never scored', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={0} state="unscored" />)
    expect(screen.getByText('Not yet scored')).toBeInTheDocument()
    expect(screen.queryByText(/^0 - /)).not.toBeInTheDocument()
  })

  it('shows Calculating for a first score in the queue', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={0} state="calculating" />)
    expect(screen.getByText('Calculating…')).toBeInTheDocument()
    expect(screen.queryByText(/^0 - /)).not.toBeInTheDocument()
  })

  it('keeps the score of a scored asset whose rescore is queued', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    render(<RiskScoreBadge score={75} state="pending" />)
    expect(screen.getByText('75 - High')).toBeInTheDocument()
  })
})

describe('riskScoreState', () => {
  it('maps the API freshness fields', async () => {
    const { riskScoreState } = await import('../components/risk-score-badge')
    expect(riskScoreState({})).toBe('scored')
    expect(riskScoreState({ riskScored: true })).toBe('scored')
    expect(riskScoreState({ riskScored: true, riskScorePending: true })).toBe('pending')
    expect(riskScoreState({ riskScored: false })).toBe('unscored')
    expect(riskScoreState({ riskScored: false, riskScorePending: true })).toBe('calculating')
  })
})
