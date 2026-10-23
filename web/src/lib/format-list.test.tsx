import { describe, it, expect } from 'vitest'
import { renderHook } from '@testing-library/react'
import { formatList, useFormatList } from './format-list'

describe('formatList', () => {
  it('joins with commas in English and Vietnamese, no glyph', () => {
    expect(formatList(['3 new', '2 still detected', '1 closed'], 'en')).toBe(
      '3 new, 2 still detected, 1 closed'
    )
    expect(formatList(['3 mới', '2 vẫn phát hiện', '1 đã đóng'], 'vi')).toBe(
      '3 mới, 2 vẫn phát hiện, 1 đã đóng'
    )
  })

  it('drops empty parts and handles one or none', () => {
    expect(formatList(['a', null, undefined, false, '', '  ', 'b'], 'en')).toBe('a, b')
    expect(formatList(['only'], 'en')).toBe('only')
    expect(formatList([], 'en')).toBe('')
    expect(formatList([null], 'en')).toBe('')
  })

  it('does not throw on an unknown locale', () => {
    expect(formatList(['a', 'b'], 'not a locale!!')).toBe('a, b')
  })

  it('never emits a separator glyph', () => {
    expect(formatList(['a', 'b', 'c'], 'en')).not.toMatch(/[·•∙⋅|]/) // separator-ok: asserts absence
  })

  it('binds the active locale through the hook (default locale outside a provider)', () => {
    const { result } = renderHook(() => useFormatList())
    expect(result.current(['a', 'b'])).toBe('a, b')
  })
})
