import { describe, expect, it } from 'vitest'
import { validateKeyValue } from '../validation'

describe('validateKeyValue', () => {
  it('accepts a plain key', () => expect(validateKeyValue('abc12345', 'key')).toBeNull())
  it('rejects empty', () => expect(validateKeyValue('', 'key')).toBe('empty'))
  it('rejects whitespace', () => {
    expect(validateKeyValue('a b', 'key')).toBe('whitespace')
    expect(validateKeyValue('a\nb', 'key')).toBe('whitespace')
  })
  it('rejects over 1024 characters', () => {
    expect(validateKeyValue('a'.repeat(1024), 'key')).toBeNull()
    expect(validateKeyValue('a'.repeat(1025), 'key')).toBe('tooLong')
  })
  it('rejects a secret shorter than 8', () => {
    expect(validateKeyValue('abc1234', 'key')).toBe('tooShort')
    expect(validateKeyValue('tok:org1234', 'pair')).toBe('tooShort')
  })
  it('pair needs a first part and a secret after the last colon', () => {
    expect(validateKeyValue('tok:org-0001', 'pair')).toBeNull()
    expect(validateKeyValue('https://reconapi.example.test/v1:key-0001', 'pair')).toBeNull()
    expect(validateKeyValue('tok', 'pair')).toBe('pairFormat')
    expect(validateKeyValue(':org-0001', 'pair')).toBe('pairFormat')
    expect(validateKeyValue('tok:', 'pair')).toBe('pairFormat')
  })
  it('a colon is fine in a single-value key', () =>
    expect(validateKeyValue('a:b-0001', 'key')).toBeNull())
})
