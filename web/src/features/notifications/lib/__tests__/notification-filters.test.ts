import { describe, it, expect } from 'vitest'
import {
  EMPTY_EVENT_TYPES_MESSAGE,
  EMPTY_SEVERITIES_MESSAGE,
  coversAllSeverities,
  enabledEventTypesSchema,
  enabledSeveritiesSchema,
} from '../notification-filters'

describe('notification channel filters', () => {
  it('refuses an empty severity list (the API would reload it as the defaults)', () => {
    const r = enabledSeveritiesSchema.safeParse([])
    expect(r.success).toBe(false)
    expect(r.error?.issues[0].message).toBe(EMPTY_SEVERITIES_MESSAGE)
    expect(enabledSeveritiesSchema.safeParse(['low']).success).toBe(true)
  })

  it('refuses an empty event-type list', () => {
    const r = enabledEventTypesSchema.safeParse([])
    expect(r.success).toBe(false)
    expect(r.error?.issues[0].message).toBe(EMPTY_EVENT_TYPES_MESSAGE)
  })

  it('"All severities" only when every real severity is enabled', () => {
    expect(coversAllSeverities(['critical', 'high', 'medium', 'low', 'info'])).toBe(true)
    expect(coversAllSeverities(['critical', 'high', 'medium', 'low', 'info', 'none'])).toBe(true)
    // Five of six, but without Critical: not "all".
    expect(coversAllSeverities(['high', 'medium', 'low', 'info', 'none'])).toBe(false)
    expect(coversAllSeverities([])).toBe(false)
    expect(coversAllSeverities(undefined)).toBe(false)
  })
})
