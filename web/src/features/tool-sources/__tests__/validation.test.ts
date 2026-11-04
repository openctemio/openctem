import { describe, expect, it } from 'vitest'
import { validateKeyValue } from '../validation'

describe('validateKeyValue', () => {
  it('accepts a plain key', () => expect(validateKeyValue('abc123', 'key')).toBeNull())
  it('rejects empty', () => expect(validateKeyValue('', 'key')).toBe('empty'))
  it('rejects whitespace', () => {
    expect(validateKeyValue('a b', 'key')).toBe('whitespace')
    expect(validateKeyValue('a\nb', 'key')).toBe('whitespace')
  })
  it('rejects over 1024 characters', () => {
    expect(validateKeyValue('a'.repeat(1024), 'key')).toBeNull()
    expect(validateKeyValue('a'.repeat(1025), 'key')).toBe('tooLong')
  })
  it('pair needs exactly one colon with both parts', () => {
    expect(validateKeyValue('tok:org', 'pair')).toBeNull()
    expect(validateKeyValue('tok', 'pair')).toBe('pairFormat')
    expect(validateKeyValue('a:b:c', 'pair')).toBe('pairFormat')
    expect(validateKeyValue(':org', 'pair')).toBe('pairFormat')
    expect(validateKeyValue('tok:', 'pair')).toBe('pairFormat')
  })
  it('a colon is fine in a single-value key', () =>
    expect(validateKeyValue('a:b', 'key')).toBeNull())
})
