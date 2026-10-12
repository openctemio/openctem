import { describe, expect, it } from 'vitest'

import { API_KEY_EXPIRY_OPTIONS, DEFAULT_API_KEY_EXPIRY_DAYS } from '../expiry'

describe('API key lifetimes', () => {
  it('offers only what the API accepts (1 to 365 days), never "never"', () => {
    for (const o of API_KEY_EXPIRY_OPTIONS) {
      const days = Number(o.value)
      expect(Number.isInteger(days) && days >= 1 && days <= 365).toBe(true)
      expect(o.label.toLowerCase()).not.toContain('never')
    }
    expect(API_KEY_EXPIRY_OPTIONS.map((o) => o.value)).toContain(DEFAULT_API_KEY_EXPIRY_DAYS)
  })
})
