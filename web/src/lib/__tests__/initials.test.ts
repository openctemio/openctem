import { describe, it, expect } from 'vitest'
import { initials } from '../initials'

describe('initials', () => {
  it('takes the first letter of the first and last word', () => {
    expect(initials('Lan Anh')).toBe('LA')
    expect(initials('Nguyen Van Minh')).toBe('NM')
    expect(initials('admin')).toBe('A')
  })
  it('keeps accented letters whole and ignores extra spaces', () => {
    expect(initials('  Đặng   Ánh ')).toBe('ĐÁ')
  })
  it('falls back to ? without a name', () => {
    expect(initials('')).toBe('?')
    expect(initials(undefined)).toBe('?')
  })
})
