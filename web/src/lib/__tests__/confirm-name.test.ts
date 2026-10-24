import { describe, expect, it } from 'vitest'
import { confirmNameFor } from '../confirm-name'

describe('confirmNameFor', () => {
  it('uses the trimmed name', () => {
    expect(confirmNameFor('  Analyst ', 'abcdef123456')).toBe('Analyst')
  })
  it('falls back to a short id when the name is empty or too long', () => {
    expect(confirmNameFor('', 'abcdef123456')).toBe('abcdef12')
    expect(confirmNameFor(undefined, 'abcdef123456')).toBe('abcdef12')
    expect(confirmNameFor('x'.repeat(65), 'abcdef123456')).toBe('abcdef12')
  })
})
