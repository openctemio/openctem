import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { ALERT_STATE_TONE, LevelBadge } from './bits'

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
})
