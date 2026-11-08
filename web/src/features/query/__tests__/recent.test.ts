import { beforeEach, describe, expect, it } from 'vitest'
import { MAX_RECENT, clearRecentQueries, pushRecent, readRecent } from '../lib/recent'

describe('recent queries', () => {
  beforeEach(() => window.localStorage.clear())

  it('keeps the newest first, without duplicates, per scope, at most MAX_RECENT', () => {
    pushRecent('findings', 'kev=true')
    pushRecent('findings', 'severity>=high')
    pushRecent('findings', 'kev=true')
    pushRecent('assets', 'ip=10.0.0.0/8')
    expect(readRecent('findings')).toEqual(['kev=true', 'severity>=high'])
    for (let i = 0; i < MAX_RECENT + 5; i++) pushRecent('findings', `q${i}`)
    expect(readRecent('findings')).toHaveLength(MAX_RECENT)
  })

  it('is cleared at sign-out, and nothing else is', () => {
    window.localStorage.setItem('other-key', 'kept')
    pushRecent('findings', 'kev=true')
    pushRecent('assets', 'ip=10.0.0.0/8')
    clearRecentQueries()
    expect(readRecent('findings')).toEqual([])
    expect(readRecent('assets')).toEqual([])
    expect(window.localStorage.getItem('other-key')).toBe('kept')
  })

  it('survives broken storage', () => {
    window.localStorage.setItem('recent-queries:findings', '{not json')
    expect(readRecent('findings')).toEqual([])
  })
})
