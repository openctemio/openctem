import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { AffectedCell, ALERT_STATE_TONE, hostTierParts, LevelBadge } from './bits'

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
