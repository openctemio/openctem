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
  it.each([
    [95, 'Critical'],
    [75, 'High'],
    [55, 'Medium'],
    [35, 'Low'],
    [15, 'Minimal'],
    // Custom thresholds (critical_min=90): 85 is High, not Critical.
    [85, 'High'],
  ])('shows %s with its band %s in the name and tooltip, never as text', async (score, band) => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    const { container } = render(<RiskScoreBadge score={score} />)
    const el = container.querySelector('[data-slot="severity-badge"]')!
    // Criticality uses the same words; the visible text is the number only.
    expect(el.textContent).toBe(String(score))
    expect(el.getAttribute('aria-label')).toBe(`Risk ${score} of 100, ${band}`)
    expect(el.getAttribute('title')).toBe(`Risk ${score} of 100, ${band}`)
  })

  it('names itself in the text when labelled (phone cards, headers)', async () => {
    const { RiskScoreBadge } = await import('../components/risk-score-badge')
    const { container } = render(<RiskScoreBadge score={73} labelled />)
    expect(container.textContent).toBe('Risk: 73')
    expect(screen.queryByText(/High/)).not.toBeInTheDocument()
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
    const { container } = render(<RiskScoreBadge score={0} />)
    expect(container.textContent).toBe('No open risk')
    expect(container.querySelector('[aria-label="Risk: No open risk"]')).not.toBeNull()
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
    expect(screen.getByText('75')).toBeInTheDocument()
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
