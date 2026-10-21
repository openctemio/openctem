import { describe, expect, it } from 'vitest'
import { ApiClientError } from '@/lib/api/error-handler'
import { belowThresholdOf } from '../create-ticket-dialog'

describe('belowThresholdOf', () => {
  it('reads the policy of a 409 TICKET_BELOW_THRESHOLD', () => {
    const err = new ApiClientError('below', 'TICKET_BELOW_THRESHOLD', 409, {
      min_severity: 'high',
      min_priority_class: 'P1',
    })
    expect(belowThresholdOf(err)).toEqual({ min_severity: 'high', min_priority_class: 'P1' })
  })

  it('ignores every other error', () => {
    expect(belowThresholdOf(new ApiClientError('x', 'TICKET_EGRESS_REFUSED', 403))).toBeNull()
    expect(belowThresholdOf(new Error('x'))).toBeNull()
  })
})
