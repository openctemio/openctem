import { describe, it, expect } from 'vitest'
import { SCHEDULE_TYPES, SCHEDULE_TYPE_LABELS } from '../scan-types'

describe('schedule types', () => {
  it('label every schedule type the API accepts, rrule included', () => {
    expect(SCHEDULE_TYPES).toContain('rrule')
    for (const t of SCHEDULE_TYPES) {
      expect(SCHEDULE_TYPE_LABELS[t]).toBeTruthy()
    }
    expect(SCHEDULE_TYPE_LABELS.rrule).toBe('Recurrence rule')
  })
})
