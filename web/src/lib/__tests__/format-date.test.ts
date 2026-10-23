import { describe, it, expect } from 'vitest'
import { formatRelative } from '../format-date'

const threeDaysAgo = new Date(Date.now() - 3 * 86400_000)

describe('formatRelative', () => {
  it('is English without a locale', () => {
    expect(formatRelative(threeDaysAgo)).toBe('3 days ago')
  })
  it('follows the app locale', () => {
    expect(formatRelative(threeDaysAgo, '—', 'vi')).toMatch(/3 ngày/)
  })
  it('falls back for an unknown locale and for invalid input', () => {
    expect(formatRelative(threeDaysAgo, '—', 'xx')).toBe('3 days ago')
    expect(formatRelative('nope', 'n/a', 'vi')).toBe('n/a')
  })
})
