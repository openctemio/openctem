import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ParseResult } from '@/features/query/api/query-api'

const api = vi.hoisted(() => ({ parse: vi.fn(), post: vi.fn() }))
vi.mock('@/features/query/api/query-api', () => ({ queryApi: { parse: api.parse } }))
vi.mock('@/lib/api/client', () => ({ post: api.post, get: vi.fn() }))

import { AdvancedScanFilterError, fetchAdvancedScans } from '../advanced-fetch'

function result(over: Partial<ParseResult>): ParseResult {
  return {
    entity: 'scans',
    valid: true,
    text: '',
    query: '',
    chips: [],
    advanced: false,
    problems: [],
    ...over,
  }
}

describe('the scans list for an fq filter', () => {
  beforeEach(() => {
    api.parse.mockReset()
    api.post.mockReset()
  })

  it('checks the page params and the text, then sends the document to /scans/search', async () => {
    api.parse
      .mockResolvedValueOnce(result({ text: 'status=active' }))
      .mockResolvedValueOnce(result({ text: 'x', document: { v: 1, filter: { any: [] } } }))
    api.post.mockResolvedValue({ data: [], total: 0 })
    await fetchAdvancedScans(
      '/api/v1/scans?status=active&page=2&per_page=50&sort=-total_runs&include_ad_hoc=true&fq=status%3Dpaused+OR+total_runs%3E%3D3'
    )
    expect(api.parse).toHaveBeenNthCalledWith(1, { entity: 'scans', params: 'status=active' })
    expect(api.parse).toHaveBeenNthCalledWith(2, {
      entity: 'scans',
      text: '(status=active) (status=paused OR total_runs>=3)',
    })
    expect(api.post).toHaveBeenCalledWith('/api/v1/scans/search?include_ad_hoc=true', {
      v: 1,
      filter: { any: [] },
      sort: ['-total_runs'],
      page: { page: 2, per_page: 50 },
    })
  })

  it('sends only the text when the page has no other filter, and leaves one-off scans out', async () => {
    api.parse.mockResolvedValueOnce(result({ text: 'x', document: { v: 1 } }))
    api.post.mockResolvedValue({ data: [], total: 0 })
    await fetchAdvancedScans('/api/v1/scans?fq=total_runs%3E%3D3')
    expect(api.parse).toHaveBeenCalledTimes(1)
    expect(api.post).toHaveBeenCalledWith('/api/v1/scans/search', {
      v: 1,
      page: { page: 1, per_page: 20 },
    })
  })

  it('refuses rather than widening: an invalid filter runs nothing', async () => {
    api.parse.mockResolvedValue(
      result({
        valid: false,
        problems: [{ code: 'unknown_field', message: '', start: 0, end: 1, line: 1, column: 1 }],
      })
    )
    await expect(fetchAdvancedScans('/api/v1/scans?fq=foo%3Dbar')).rejects.toBeInstanceOf(
      AdvancedScanFilterError
    )
    expect(api.post).not.toHaveBeenCalled()
  })
})
