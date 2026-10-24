import { describe, expect, it } from 'vitest'
import { confirmName } from '../confirm-name'

describe('confirmName', () => {
  it('uses the trimmed name when it is short', () => {
    expect(confirmName('  SQL injection  ', 'abcdef123456')).toBe('SQL injection')
  })
  it('falls back to the short id for an empty or long name', () => {
    expect(confirmName('', 'abcdef123456')).toBe('abcdef12')
    expect(confirmName(null, 'abcdef123456')).toBe('abcdef12')
    expect(confirmName('x'.repeat(65), 'abcdef123456')).toBe('abcdef12')
    expect(confirmName('x'.repeat(64), 'abcdef123456')).toBe('x'.repeat(64))
  })
})
