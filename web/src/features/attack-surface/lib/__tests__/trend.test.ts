import { describe, expect, it } from 'vitest'
import { newInWindow } from '../trend'

describe('newInWindow', () => {
  it('states zero instead of hiding the caption', () => {
    expect(newInWindow(0, 7)).toBe('0 new in the last 7 days')
    expect(newInWindow(undefined, 7)).toBe('0 new in the last 7 days')
  })
  it('uses the noun and window from the API', () => {
    expect(newInWindow(3, 7, 'newly exposed')).toBe('3 newly exposed in the last 7 days')
    expect(newInWindow(12, 30)).toBe('12 new in the last 30 days')
  })
})
