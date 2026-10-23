import { describe, expect, it } from 'vitest'
import { safeInternalHref } from '../safe-href'

describe('safeInternalHref', () => {
  it.each([
    'https://evil.example',
    'http://evil.example/x',
    '//evil',
    '/\\evil',
    '\\\\evil',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'evil.example/x',
    '',
    '   ',
  ])('refuses %j', (value) => {
    expect(safeInternalHref(value)).toBeUndefined()
  })

  it('refuses non-strings', () => {
    expect(safeInternalHref(undefined)).toBeUndefined()
    expect(safeInternalHref(null)).toBeUndefined()
    expect(safeInternalHref(42)).toBeUndefined()
  })

  it('accepts same-origin paths', () => {
    expect(safeInternalHref('/findings/123')).toBe('/findings/123')
    expect(safeInternalHref('/findings?x=1#c')).toBe('/findings?x=1#c')
  })
})
