import { describe, expect, it } from 'vitest'

import {
  apiTargetOptions,
  describeTargetOptions,
  hasCidrTarget,
  hasDynamicTargets,
  seenSince,
  selectorPreviewURL,
  selectorsOf,
  toWildcards,
} from '../dynamic-targets'

describe('selectorsOf', () => {
  it('finds every wildcard, once, with its apex', () => {
    expect(
      selectorsOf(['*.Example.com', 'a.example.org', '*.example.com', '203.0.113.0/24'])
    ).toEqual([{ kind: 'wildcard', target: '*.Example.com', value: 'example.com' }])
  })

  it('treats a CIDR as a selector only in inventory mode', () => {
    expect(selectorsOf(['203.0.113.0/24'], { cidr_mode: 'sweep' })).toEqual([])
    expect(selectorsOf(['203.0.113.0/24'], { cidr_mode: 'inventory' })).toEqual([
      { kind: 'cidr', target: '203.0.113.0/24', value: '203.0.113.0/24' },
    ])
    expect(hasCidrTarget(['example.com', '203.0.113.0/24'])).toBe(true)
    expect(hasDynamicTargets(['203.0.113.0/24'])).toBe(false)
    expect(hasDynamicTargets(['*.example.com'])).toBe(true)
  })
})

describe('toWildcards', () => {
  it('turns typed domains into *.domain and keeps everything else', () => {
    expect(
      toWildcards([
        'Example.com',
        'https://app.example.org/x',
        '203.0.113.7',
        '*.example.com',
        'example.com',
      ])
    ).toEqual(['*.example.com', 'https://app.example.org/x', '203.0.113.7'])
  })
})

describe('apiTargetOptions', () => {
  it('sends only what differs from the defaults', () => {
    expect(apiTargetOptions(undefined)).toBeUndefined()
    expect(
      apiTargetOptions({ cidr_mode: 'sweep', seen_within_days: 0, include_stale: false })
    ).toBeUndefined()
    expect(
      apiTargetOptions({ cidr_mode: 'inventory', seen_within_days: 30, include_stale: true })
    ).toEqual({
      cidr_mode: 'inventory',
      seen_within_days: 30,
      include_stale: true,
    })
  })
})

describe('selectorPreviewURL', () => {
  const now = new Date('2026-10-09T12:00:00Z')

  it('asks for the active names under the apex, freshest first', () => {
    const url = new URL(
      selectorPreviewURL(
        { kind: 'wildcard', target: '*.example.com', value: 'example.com' },
        undefined,
        5,
        now
      ),
      'http://x'
    )
    expect(url.pathname).toBe('/api/v1/assets')
    expect(url.searchParams.get('under')).toBe('example.com')
    expect(url.searchParams.get('types')).toBe('domain,subdomain')
    expect(url.searchParams.get('statuses')).toBe('active')
    expect(url.searchParams.get('sort')).toBe('-last_seen')
    expect(url.searchParams.get('last_seen_after')).toBeNull()
  })

  it('follows the options, and asks for addresses inside a range', () => {
    const url = new URL(
      selectorPreviewURL(
        { kind: 'cidr', target: '203.0.113.0/24', value: '203.0.113.0/24' },
        { include_stale: true, seen_within_days: 7 },
        5,
        now
      ),
      'http://x'
    )
    expect(url.searchParams.get('in_cidr')).toBe('203.0.113.0/24')
    expect(url.searchParams.get('under')).toBeNull()
    expect(url.searchParams.get('statuses')).toBe('active,stale,inactive')
    expect(url.searchParams.get('last_seen_after')).toBe('2026-10-02')
    expect(seenSince(30, now)).toBe('2026-09-09')
  })
})

describe('describeTargetOptions', () => {
  it('says how ranges and selectors are resolved', () => {
    expect(describeTargetOptions(['203.0.113.0/24'], undefined)).toEqual(['Ranges: swept whole'])
    expect(
      describeTargetOptions(['*.example.com', '203.0.113.0/24'], {
        cidr_mode: 'inventory',
        seen_within_days: 30,
        include_stale: true,
      })
    ).toEqual([
      'Ranges: only the hosts in the inventory',
      'Only assets seen in the last 30 days',
      'Includes stale assets',
    ])
    expect(describeTargetOptions(['example.com'], { seen_within_days: 30 })).toEqual([])
  })
})
