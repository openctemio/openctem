import { describe, expect, it } from 'vitest'
import { CYCLE_STATUS_TONE } from './cycle-status-badge'
import { OUTCOME_HEALTH } from '../charter-outcome'

describe('cycle tone maps', () => {
  it('maps every cycle status to its workflow tone', () => {
    expect(
      Object.fromEntries(Object.entries(CYCLE_STATUS_TONE).map(([k, v]) => [k, v.tone]))
    ).toEqual({
      planning: 'open',
      active: 'progress',
      review: 'waiting',
      closed: 'resolved',
    })
  })

  it('maps every charter outcome to a health state', () => {
    expect(OUTCOME_HEALTH).toEqual({ met: 'ok', unmet: 'down', not_measurable: 'unknown' })
  })
})
