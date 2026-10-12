import { describe, expect, it } from 'vitest'
import { changesRequestUrl, isChangeKind, parseTime, CHANGE_KINDS } from '../changes'

describe('changesRequestUrl', () => {
  const now = new Date('2026-10-11T00:00:00Z')

  it('asks for the last N days with the kinds and a page size', () => {
    const url = new URL(
      changesRequestUrl({ days: 7, kinds: ['host_added', 'dns_dangling'] }, undefined, now),
      'http://x'
    )
    expect(url.pathname).toBe('/api/v1/easm/changes')
    expect(url.searchParams.get('from')).toBe('2026-10-04T00:00:00.000Z')
    expect(url.searchParams.get('to')).toBeNull()
    expect(url.searchParams.get('kind')).toBe('host_added,dns_dangling')
    expect(url.searchParams.get('limit')).toBe('50')
  })

  it('uses an explicit window from a digest link and passes the cursor', () => {
    const url = new URL(
      changesRequestUrl(
        { days: 7, kinds: [], from: '2026-10-05T08:00:00.000Z', to: '2026-10-12T08:00:00.000Z' },
        'abc',
        now
      ),
      'http://x'
    )
    expect(url.searchParams.get('from')).toBe('2026-10-05T08:00:00.000Z')
    expect(url.searchParams.get('to')).toBe('2026-10-12T08:00:00.000Z')
    expect(url.searchParams.get('kind')).toBeNull()
    expect(url.searchParams.get('cursor')).toBe('abc')
  })

  it('clamps the window to the 31 days the API allows', () => {
    const url = new URL(changesRequestUrl({ days: 90, kinds: [] }, undefined, now), 'http://x')
    expect(url.searchParams.get('from')).toBe('2026-09-10T00:00:00.000Z')
  })
})

describe('kinds and times', () => {
  it('knows the ten kinds', () => {
    expect(CHANGE_KINDS).toHaveLength(10)
    expect(isChangeKind('cert_expiring')).toBe(true)
    expect(isChangeKind('nope')).toBe(false)
  })
  it('accepts only valid times', () => {
    expect(parseTime('2026-10-05T08:00:00Z')).toBe('2026-10-05T08:00:00.000Z')
    expect(parseTime('yesterday')).toBeUndefined()
    expect(parseTime(null)).toBeUndefined()
  })
})
