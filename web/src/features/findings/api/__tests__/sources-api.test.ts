import { describe, expect, it } from 'vitest'

import { findingSourcesUrl } from '../sources-api'

describe('findingSourcesUrl', () => {
  it('reads /source-records, not /sources (which would shadow the removed analytics path)', () => {
    expect(findingSourcesUrl('a/b')).toBe('/api/v1/findings/a%2Fb/source-records')
  })
})
