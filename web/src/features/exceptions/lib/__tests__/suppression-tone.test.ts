import { describe, expect, it } from 'vitest'
import { SUPPRESSION_STATUS_TONE, SUPPRESSION_TYPE_ICON } from '../suppression-tone'

describe('exception tone maps', () => {
  it('maps every approval status to its workflow tone', () => {
    const tones = Object.fromEntries(
      Object.entries(SUPPRESSION_STATUS_TONE).map(([k, v]) => [k, v.tone])
    )
    expect(tones).toEqual({
      pending: 'waiting',
      approved: 'resolved',
      rejected: 'closed',
      expired: 'closed',
    })
  })

  it('gives every exception type an icon and no colour map', () => {
    expect(Object.keys(SUPPRESSION_TYPE_ICON).sort()).toEqual([
      'accepted_risk',
      'false_positive',
      'wont_fix',
    ])
  })
})
