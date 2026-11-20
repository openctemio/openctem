import { describe, expect, it } from 'vitest'
import { isWebOriginType } from '../components/origin-web-section'
import {
  DEFAULT_PATH_FILTERS,
  isParamSegment,
  normalizeNodePath,
  parentPath,
  pathFiltersChanged,
  pathTrail,
  pathUnder,
  webPathsUrl,
} from '../lib/web-paths-url'

describe('web paths url', () => {
  it('builds one level with the default filters', () => {
    expect(webPathsUrl('a1', '/', DEFAULT_PATH_FILTERS)).toBe(
      '/api/v1/assets/a1/web-paths?hide_static=true&per_page=50'
    )
  })

  it('encodes the node, the filters and the paging', () => {
    const url = webPathsUrl(
      'a/1',
      '/api/users/{int}',
      { ...DEFAULT_PATH_FILTERS, hide4xx: true, scope: 'out', method: 'POST', q: 'adm in' },
      { here: true, findings: true, page: 3, perPage: 0 }
    )
    expect(url.startsWith('/api/v1/assets/a%2F1/web-paths?')).toBe(true)
    const q = new URLSearchParams(url.split('?')[1])
    expect(q.get('path')).toBe('/api/users/{int}')
    expect(q.get('q')).toBe('adm in')
    expect(q.get('hide_4xx')).toBe('true')
    expect(q.get('scope')).toBe('out')
    expect(q.get('method')).toBe('POST')
    expect(q.get('here')).toBe('true')
    expect(q.get('findings')).toBe('true')
    expect(q.get('page')).toBe('3')
    expect(q.get('per_page')).toBe('0')
  })

  it('accepts only node paths the API accepts', () => {
    expect(normalizeNodePath('/api/')).toBe('/api')
    expect(normalizeNodePath('/api/users')).toBe('/api/users')
    for (const bad of ['', 'api', '//x', '/a?b', '/a#b', '/a\\b', null, undefined]) {
      expect(normalizeNodePath(bad)).toBe('/')
    }
  })

  it('walks the trail and the parent', () => {
    expect(pathTrail('/')).toEqual([])
    expect(pathTrail('/api/{int}')).toEqual([
      { name: 'api', path: '/api' },
      { name: '{int}', path: '/api/{int}' },
    ])
    expect(parentPath('/api/{int}')).toBe('/api')
    expect(parentPath('/api')).toBe('/')
    expect(isParamSegment('{uuid}')).toBe(true)
    expect(isParamSegment('users')).toBe(false)
  })

  it('shows a template relative to the selected node', () => {
    expect(pathUnder('/api/v1/orders/{int}/history', '/')).toBe('/api/v1/orders/{int}/history')
    expect(pathUnder('/api/v1/orders/{int}/history', '/api/v1/orders')).toBe('\u2026/{int}/history')
    expect(pathUnder('/api/v1/orders', '/api/v1/orders')).toBe('\u2026/orders')
  })

  it('tells when filters differ from the defaults', () => {
    expect(pathFiltersChanged(DEFAULT_PATH_FILTERS)).toBe(false)
    expect(pathFiltersChanged({ ...DEFAULT_PATH_FILTERS, hideStatic: false })).toBe(true)
    expect(pathFiltersChanged({ ...DEFAULT_PATH_FILTERS, q: 'x' })).toBe(true)
  })
})

describe('isWebOriginType', () => {
  it('knows an origin stored as a service with the http sub-type, and the legacy names', () => {
    expect(isWebOriginType('service', 'http')).toBe(true)
    expect(isWebOriginType('http_service')).toBe(true)
    expect(isWebOriginType('website')).toBe(true)
    expect(isWebOriginType('service', 'ssh')).toBe(false)
    expect(isWebOriginType('domain')).toBe(false)
  })
})
