import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import {
  AffectedCell,
  ALERT_STATE_TONE,
  EtsBreakdownBars,
  explainedParts,
  hostTierParts,
  LevelBadge,
  ScoreCell,
} from './bits'

describe('emerging alert labels', () => {
  it('maps every alert state to its workflow tone', () => {
    expect(
      Object.fromEntries(Object.entries(ALERT_STATE_TONE).map(([k, v]) => [k, v.tone]))
    ).toEqual({
      new: 'triage',
      acknowledged: 'open',
      remediating: 'progress',
      resolved: 'resolved',
      not_affected: 'closed',
    })
  })

  it('shows only an immediate alert in the alert tone', () => {
    const imm = render(<LevelBadge level="immediate" />)
    expect(imm.container.querySelector('[data-level="immediate"]')).toBeTruthy()
    const dig = render(<LevelBadge level="digest" />)
    expect(dig.container.innerHTML).not.toMatch(/destructive/)
  })

  it('names host counts in the words messages use: the first tier carries "host"', () => {
    const t = (key: string, _f?: string, vars?: Record<string, unknown>) =>
      `${key.replace('emergingThreats.affected.', '')}:${vars?.n}`
    const texts = (c: { confirmed: number; likely: number; possible: number }) =>
      hostTierParts(t as never, c).map((p) => p.text)
    expect(texts({ confirmed: 3, likely: 1, possible: 2 })).toEqual([
      'first.confirmed:3',
      'more.likely:1',
      'more.possible:2',
    ])
    expect(texts({ confirmed: 1, likely: 0, possible: 0 })).toEqual(['first.confirmedOne:1'])
    expect(texts({ confirmed: 0, likely: 2, possible: 1 })).toEqual([
      'first.likely:2',
      'more.possible:1',
    ])
    expect(texts({ confirmed: 0, likely: 0, possible: 1 })).toEqual(['first.possibleOne:1'])
    expect(texts({ confirmed: 0, likely: 0, possible: 0 })).toEqual([])
  })

  it('the affected cell keeps likely apart from confirmed and never says assets', () => {
    const { container } = render(
      <AffectedCell confirmed={1} likely={2} possible={0} internet={0} critical={0} />
    )
    const cell = container.querySelector('[data-slot="affected-cell"]') as HTMLElement
    expect(cell.querySelector('[data-tier="confirmed"]')?.textContent).toBe('1 host confirmed')
    expect(cell.querySelector('[data-tier="likely"]')?.textContent).toBe('+2 likely')
    expect(cell.querySelector('[data-tier="possible"]')).toBeNull()
    expect(cell.getAttribute('aria-label')).toMatch(/^Affected hosts: 1 confirmed, 2 likely/)
    expect(`${cell.textContent} ${cell.getAttribute('aria-label')}`).not.toMatch(/assets/i)
  })
})

describe('the score and its parts', () => {
  const parts = {
    exploitation: 40,
    severity: 20,
    exposure: 20,
    freshness: 10,
    confidence: 1,
    total: 90,
  }

  it('keeps parts only when they give the score', () => {
    expect(explainedParts(90, parts)).toBe(parts)
    expect(explainedParts(45, { ...parts, confidence: 0.5, total: 45 })).not.toBeNull()
    expect(
      explainedParts(100, { ...parts, exploitation: 45, severity: 25, exposure: 30, total: 100 })
    ).not.toBeNull()
    // The acceptance bug: score 87, every part 0.
    const zero = {
      exploitation: 0,
      severity: 0,
      exposure: 0,
      freshness: 0,
      confidence: 0,
      total: 0,
    }
    expect(explainedParts(87, zero)).toBeNull()
    expect(explainedParts(87, null)).toBeNull()
    expect(explainedParts(87, parts)).toBeNull()
    expect(explainedParts(87, { ...parts, total: 87 })).toBeNull()
    expect(explainedParts(90, { ...parts, confidence: 2 })).toBeNull()
    expect(explainedParts(90, { ...parts, severity: -10, exploitation: 70 })).toBeNull()
  })

  it('shows a total equal to the score and says how the points make it', () => {
    const { container, getByText } = render(<EtsBreakdownBars ets={90} breakdown={parts} />)
    const total = container.querySelector(
      '[data-slot=ets-breakdown] p span:last-child span:last-child'
    )
    expect(total?.textContent).toBe('90')
    expect(getByText(/every point counts: 90 points make a score of 90/)).toBeInTheDocument()
    const scaled = render(
      <EtsBreakdownBars ets={45} breakdown={{ ...parts, confidence: 0.5, total: 45 }} />
    )
    expect(scaled.getByText(/50% of the points count: 90 × 0.5 = 45/)).toBeInTheDocument()
  })

  it('never shows zeroed parts beside a score they do not give', () => {
    const zero = {
      exploitation: 0,
      severity: 0,
      exposure: 0,
      freshness: 0,
      confidence: 0,
      total: 0,
    }
    for (const b of [zero, null]) {
      const { container, unmount } = render(<EtsBreakdownBars ets={87} breakdown={b} />)
      expect(container.querySelector('[data-slot=ets-breakdown]')).toBeNull()
      expect(container.querySelector('[data-slot=ets-breakdown-unrecorded]')?.textContent).toMatch(
        /were not recorded/
      )
      unmount()
    }
    // The list cell shows the score with no tooltip of parts.
    const cell = render(<ScoreCell ets={87} breakdown={zero} />)
    expect(cell.container.querySelector('button')).toBeNull()
    expect(cell.container.textContent).toContain('87')
  })
})
