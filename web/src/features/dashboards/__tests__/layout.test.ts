import { describe, expect, it } from 'vitest'
import { columnsClass, phoneSpan, widgetSpanClass } from '../layout'

describe('dashboard grid on a phone', () => {
  it('a four-column dashboard is two columns from the smallest phone', () => {
    expect(columnsClass(4)).toBe('grid-cols-2 xl:grid-cols-4')
    expect(widgetSpanClass(4)).toContain('[grid-column:var(--span-xs)]')
  })

  it('single-figure tiles (one column, one row) sit two abreast; everything else takes the row', () => {
    expect(phoneSpan(3, 1, 4)).toBe('span 1 / span 1')
    expect(phoneSpan(3, 2, 4)).toBe('span 2 / span 2')
    expect(phoneSpan(6, 1, 4)).toBe('span 2 / span 2')
    expect(phoneSpan(12, 2, 4)).toBe('span 2 / span 2')
  })

  it('other column counts keep one column on a phone', () => {
    expect(columnsClass(1)).toBe('grid-cols-1')
    expect(columnsClass(3)).toMatch(/^grid-cols-1 /)
    expect(columnsClass(2)).toMatch(/^grid-cols-1 /)
  })
})
