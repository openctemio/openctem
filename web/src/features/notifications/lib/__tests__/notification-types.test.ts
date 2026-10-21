import { describe, it, expect } from 'vitest'
import { NOTIFICATION_TYPES, NOTIFICATION_TYPE_LABELS } from '../notification-types'

describe('NOTIFICATION_TYPES', () => {
  it('does not offer a preference for a notification nothing sends yet', () => {
    const ids = NOTIFICATION_TYPES.map((t) => t.id)
    expect(ids).not.toContain('finding_mention')
    expect(NOTIFICATION_TYPE_LABELS.finding_mention).toBeUndefined()
  })

  it('lists each type once, with a name and a description', () => {
    const ids = NOTIFICATION_TYPES.map((t) => t.id)
    expect(new Set(ids).size).toBe(ids.length)
    for (const t of NOTIFICATION_TYPES) {
      expect(t.name.length).toBeGreaterThan(0)
      expect(t.description.length).toBeGreaterThan(0)
    }
  })
})
