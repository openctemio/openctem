import { describe, expect, it } from 'vitest'
import { parseListQuery, writeListQuery } from '../url-filters'

const parse = (qs: string) => parseListQuery(new URLSearchParams(qs))

describe('emerging-threat list filters in the URL', () => {
  it('an empty query is the default view: open alerts, page 1', () => {
    expect(parse('')).toEqual({
      level: undefined,
      state: 'open',
      tier: undefined,
      internetOnly: false,
      search: '',
      page: 1,
      perPage: 25,
    })
  })

  it('reads every filter with the list API names', () => {
    expect(
      parse(
        'level=immediate&state=resolved&tier=possible&exposure=internet&search=CVE-1&page=4&per_page=50'
      )
    ).toEqual({
      level: 'immediate',
      state: 'resolved',
      tier: 'possible',
      internetOnly: true,
      search: 'CVE-1',
      page: 4,
      perPage: 50,
    })
  })

  it('a dashboard level link opens that level of the open alerts', () => {
    expect(parse('level=digest&state=open')).toMatchObject({ level: 'digest', state: 'open' })
  })

  it('values the API would refuse fall back to the default', () => {
    expect(
      parse('level=urgent&state=closed&tier=x&exposure=yes&page=0&per_page=1000')
    ).toMatchObject({
      level: undefined,
      state: 'open',
      tier: undefined,
      internetOnly: false,
      page: 1,
      perPage: 25,
    })
    expect(parse('page=2.5&per_page=1e2')).toMatchObject({ page: 1, perPage: 25 })
    expect(parse('page=0x10')).toMatchObject({ page: 1 })
  })

  it('writes only non-default values and keeps other parameters', () => {
    const base = new URLSearchParams('keep=1&level=listed&page=9')
    expect(writeListQuery(base, parse('')).toString()).toBe('keep=1')
    expect(
      writeListQuery(base, {
        level: 'immediate',
        state: 'all',
        tier: 'confirmed',
        internetOnly: true,
        search: 'log4j',
        page: 2,
        perPage: 50,
      }).toString()
    ).toBe(
      'keep=1&level=immediate&state=all&tier=confirmed&exposure=internet&search=log4j&page=2&per_page=50'
    )
  })

  it('round-trips', () => {
    const qs = 'level=immediate&state=new&exposure=internet&search=a+b&page=3'
    expect(writeListQuery(new URLSearchParams(), parse(qs)).toString()).toBe(qs)
  })
})
