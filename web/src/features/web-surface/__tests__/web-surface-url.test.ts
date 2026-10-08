import { describe, expect, it } from 'vitest'
import {
  endpointParamsUrl,
  endpointStatsUrl,
  endpointsUrl,
  eventsUrl,
  isWebSurfaceTab,
  originsUrl,
  patternsUrl,
} from '../lib/web-surface-url'

const page = { page: 2, perPage: 50 }

describe('web surface URLs', () => {
  it('sends only the filters that are set, with the list paging', () => {
    const url = new URL(endpointsUrl({ q: ' /admin ', method: 'POST' }, page), 'http://x')
    expect(url.pathname).toBe('/api/v1/web-endpoints')
    expect(Object.fromEntries(url.searchParams)).toEqual({
      page: '2',
      per_page: '50',
      q: '/admin',
      method: 'POST',
      state: 'active,gone',
    })
  })

  it('maps the coverage-gap and sensitive toggles to the API filters', () => {
    const url = new URL(
      originsUrl({ excludedOnly: true, sensitiveOnly: true, originAssetId: 'a1' }, page),
      'http://x'
    )
    expect(url.searchParams.get('in_scope')).toBe('false')
    expect(url.searchParams.get('sensitive')).toBe('true')
    expect(url.searchParams.get('origin_asset_id')).toBe('a1')
  })

  it('shows ignored endpoints only when asked', () => {
    expect(
      new URL(patternsUrl({ includeIgnored: true }, page), 'http://x').searchParams.has('state')
    ).toBe(false)
    expect(endpointStatsUrl({})).toBe('/api/v1/web-endpoints/stats?state=active%2Cgone')
  })

  it('filters the change feed', () => {
    const url = new URL(
      eventsUrl({ kind: 'appeared', sensitiveOnly: true, since: '2026-10-01T00:00:00Z' }, page),
      'http://x'
    )
    expect(url.pathname).toBe('/api/v1/web-endpoint-events')
    expect(url.searchParams.get('kind')).toBe('appeared')
    expect(url.searchParams.get('at_gte')).toBe('2026-10-01T00:00:00Z')
  })

  it('escapes ids in paths', () => {
    expect(endpointParamsUrl('a/b')).toBe('/api/v1/web-endpoints/a%2Fb/parameters')
  })

  it('knows its tabs', () => {
    expect(isWebSurfaceTab('patterns')).toBe(true)
    expect(isWebSurfaceTab('admin')).toBe(false)
  })
})
