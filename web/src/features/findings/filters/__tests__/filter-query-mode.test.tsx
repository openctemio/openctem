import { describe, expect, it, vi, beforeEach } from 'vitest'
import { applyTextFilter, filterParams, FQ_PARAM } from '../filter-query-mode'
import type { ParseResult } from '@/features/query/api/query-api'

const api = vi.hoisted(() => ({ parse: vi.fn(), post: vi.fn() }))
vi.mock('@/features/query/api/query-api', () => ({ queryApi: { parse: api.parse } }))
vi.mock('@/lib/api/client', () => ({ post: api.post, get: vi.fn() }))

const skip = new Set(['asset_id'])

function result(over: Partial<ParseResult>): ParseResult {
  return {
    entity: 'findings',
    valid: true,
    text: '',
    query: '',
    chips: [],
    advanced: false,
    problems: [],
    ...over,
  }
}

describe('the findings text mode and the URL', () => {
  it('reads the filter part of the URL, keeping page state and context out', () => {
    const s = new URLSearchParams(
      'severity=critical&q=log4j&page=3&sort=-severity&view=v1&asset_id=a1&fq=x&state=open&density=compact'
    )
    expect(filterParams(s, skip)).toBe('severity=critical&q=log4j&state=open')
  })

  it('writes a chip filter back as flat params, so links keep their form', () => {
    const s = new URLSearchParams('severity=low&page=3&sort=-severity&asset_id=a1&fq=old')
    const next = applyTextFilter(
      s,
      skip,
      result({
        text: 'severity>=high kev=true log4j',
        params: { severity: 'critical,high', is_in_kev: 'true', q: 'log4j' },
      })
    )
    expect(next.toString()).toBe(
      'sort=-severity&asset_id=a1&severity=critical%2Chigh&is_in_kev=true&q=log4j'
    )
  })

  it('keeps a filter chips cannot show as fq, never flattened', () => {
    const next = applyTextFilter(
      new URLSearchParams('severity=low'),
      skip,
      result({ text: 'severity=critical OR is_in_kev=true', advanced: true })
    )
    expect(next.get(FQ_PARAM)).toBe('severity=critical OR is_in_kev=true')
    expect(next.get('severity')).toBeNull()
  })

  it('an empty text clears the filter', () => {
    expect(
      applyTextFilter(new URLSearchParams('severity=low&sort=x'), skip, result({})).toString()
    ).toBe('sort=x')
  })
})

describe('the list for an fq filter', () => {
  beforeEach(() => {
    api.parse.mockReset()
    api.post.mockReset()
  })

  it('checks the page params and the text, then sends the document to /findings/search', async () => {
    const { fetchAdvancedFindings } = await import('../../api/advanced-fetch')
    api.parse
      .mockResolvedValueOnce(result({ text: 'state=open' }))
      .mockResolvedValueOnce(result({ text: 'x', document: { v: 1, filter: { any: [] } } }))
    api.post.mockResolvedValue({ data: [], total: 0 })
    await fetchAdvancedFindings(
      '/api/v1/findings?state=open&page=2&per_page=50&sort=-severity&fq=severity%3Dcritical+OR+kev%3Dtrue'
    )
    expect(api.parse).toHaveBeenNthCalledWith(1, { entity: 'findings', params: 'state=open' })
    expect(api.parse).toHaveBeenNthCalledWith(2, {
      entity: 'findings',
      text: '(state=open) (severity=critical OR kev=true)',
    })
    expect(api.post).toHaveBeenCalledWith('/api/v1/findings/search', {
      v: 1,
      filter: { any: [] },
      sort: ['-severity'],
      page: { page: 2, per_page: 50 },
    })
  })

  it('refuses rather than widening: an invalid filter runs nothing', async () => {
    const { fetchAdvancedFindings } = await import('../../api/advanced-fetch')
    api.parse.mockResolvedValue(
      result({
        valid: false,
        problems: [{ code: 'unknown_field', message: '', start: 0, end: 1, line: 1, column: 1 }],
      })
    )
    await expect(fetchAdvancedFindings('/api/v1/findings?fq=foo%3Dbar')).rejects.toThrow()
    expect(api.post).not.toHaveBeenCalled()
  })
})
