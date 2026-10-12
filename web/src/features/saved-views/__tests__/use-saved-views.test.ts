import { describe, expect, it } from 'vitest'

import { savedViewId, viewQueryFromSearch } from '../api/use-saved-views'

describe('saved views helpers', () => {
  it('only a UUID is a saved view id (view=verify is page state)', () => {
    expect(savedViewId('verify')).toBeUndefined()
    expect(savedViewId('')).toBeUndefined()
    expect(savedViewId('0193e000-0000-7000-8000-000000000001')).toBe(
      '0193e000-0000-7000-8000-000000000001'
    )
  })
  it('keeps only the filter params', () => {
    expect(
      viewQueryFromSearch(
        '?severity=critical&page=3&per_page=50&view=verify&group=cve_id&q=log4j&sort=-created_at'
      )
    ).toBe('severity=critical&q=log4j&sort=-created_at')
    const id = '0193e000-0000-7000-8000-000000000001'
    expect(viewQueryFromSearch(`?view=${id}&severity=low`)).toBe(`view=${id}&severity=low`)
  })
})
