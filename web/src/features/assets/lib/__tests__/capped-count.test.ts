import { describe, expect, it } from 'vitest'
import { formatTotal } from '../capped-count'

const t = (_k: string, fb?: string, vars?: Record<string, string | number>) =>
  (fb ?? '').replace('{count}', String(vars?.count ?? ''))

describe('a capped total', () => {
  it('shows 10,000+ when the API stopped counting', () => {
    expect(formatTotal(10000, true, t)).toBe('10,000+')
  })
  it('shows the exact number otherwise', () => {
    expect(formatTotal(9999, false, t)).toBe('9,999')
    expect(formatTotal(10000, undefined, t)).toBe('10,000')
  })
})
