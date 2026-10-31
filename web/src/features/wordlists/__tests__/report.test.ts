import { describe, expect, it } from 'vitest'

import { reportText, utf8Bytes } from '../lib/report'

const t = (_key: string, fallback?: string, vars?: Record<string, string | number>) =>
  (fallback ?? '').replace(/\{(\w+)\}/g, (_, k: string) => String(vars?.[k] ?? ''))

describe('reportText', () => {
  it('says what was kept and every kind of dropped line, with examples', () => {
    expect(
      reportText(
        { kept: 412, invalid: 3, secrets: 1, duplicates: 2, examples: ['foo_bar', '*.x'] },
        t
      )
    ).toBe(
      'Kept 412 labels. Dropped 3 lines that are not DNS labels. Dropped 1 lines that look like secrets. Removed 2 repeated labels. Examples: foo_bar, *.x'
    )
  })

  it('says only what was kept when nothing was dropped', () => {
    expect(reportText({ kept: 5, invalid: 0, secrets: 0, duplicates: 0, examples: [] }, t)).toBe(
      'Kept 5 labels.'
    )
  })
})

describe('utf8Bytes', () => {
  it('counts UTF-8 bytes, not characters', () => {
    expect(utf8Bytes('học')).toBe(5)
  })
})
