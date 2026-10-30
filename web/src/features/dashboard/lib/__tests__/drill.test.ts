import { describe, expect, it } from 'vitest'

import { informationalHidden } from '@/features/findings/lib/quick-views'

import { DRILL } from '../drill'

// The dashboard's open count includes informational findings, which the
// findings list hides by default. The link must not land on a narrower list.
describe('DRILL', () => {
  it('open does not hide informational findings, whatever the account preference', () => {
    const search = DRILL.open.split('?')[1]
    expect(informationalHidden(search, false)).toBe(false)
    expect(informationalHidden(search, true)).toBe(false)
  })

  it('carries the state the figure counts', () => {
    expect(new URLSearchParams(DRILL.open.split('?')[1]).get('state')).toBe('open')
  })
})
