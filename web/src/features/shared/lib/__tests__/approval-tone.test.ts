import { describe, expect, it } from 'vitest'
import { APPROVAL_TONE } from '../approval-tone'

describe('approval tone map', () => {
  it('maps every approval status to its workflow tone', () => {
    expect(Object.fromEntries(Object.entries(APPROVAL_TONE).map(([k, v]) => [k, v.tone]))).toEqual({
      pending: 'waiting',
      approved: 'resolved',
      rejected: 'closed',
      canceled: 'closed',
      expired: 'closed',
      superseded: 'closed',
    })
  })
})
