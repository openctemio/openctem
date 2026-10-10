import { describe, expect, it } from 'vitest'

import { LETTER_MAX_BYTES, daysLeft, letterFormProblem } from '../letter-form'

const ok = {
  file: { type: 'application/pdf', size: 1000 },
  title: 'Pentest LoA',
  validFrom: '2026-10-01',
  validUntil: '2027-10-01',
}

describe('letterFormProblem', () => {
  it('accepts a complete form', () => {
    expect(letterFormProblem(ok)).toBeNull()
  })

  it('reports the first problem', () => {
    expect(letterFormProblem({ ...ok, file: null })).toBe('file_missing')
    expect(letterFormProblem({ ...ok, file: { type: 'text/html', size: 10 } })).toBe('file_type')
    expect(letterFormProblem({ ...ok, file: { type: 'image/png', size: 0 } })).toBe('file_size')
    expect(
      letterFormProblem({ ...ok, file: { type: 'image/jpeg', size: LETTER_MAX_BYTES + 1 } })
    ).toBe('file_size')
    expect(letterFormProblem({ ...ok, title: '  ' })).toBe('title_missing')
    expect(letterFormProblem({ ...ok, validUntil: '' })).toBe('dates_missing')
    expect(letterFormProblem({ ...ok, validUntil: '2026-10-01' })).toBe('dates_order')
    expect(letterFormProblem({ ...ok, validUntil: '2028-10-03' })).toBe('dates_too_long')
  })
})

describe('daysLeft', () => {
  it('counts whole days, negative once ended', () => {
    const now = Date.parse('2026-10-09T12:00:00Z')
    expect(daysLeft('2026-10-19T12:00:00Z', now)).toBe(10)
    expect(daysLeft('2026-10-08T12:00:00Z', now)).toBe(-1)
  })
})
