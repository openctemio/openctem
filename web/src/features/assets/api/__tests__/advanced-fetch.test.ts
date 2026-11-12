import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ParseResult } from '@/features/query/api/query-api'

const api = vi.hoisted(() => ({ parse: vi.fn(), post: vi.fn() }))
vi.mock('@/features/query/api/query-api', () => ({ queryApi: { parse: api.parse } }))
vi.mock('@/lib/api/client', () => ({ post: api.post, get: vi.fn() }))

import { advancedAssetsDocument, fetchAdvancedAssets } from '../advanced-fetch'

const doc = { v: 1, filter: { any: [{ field: 'port', op: 'in', value: ['22'] }] } }
function result(over: Partial<ParseResult>): ParseResult {
  return {
    entity: 'assets',
    valid: true,
    text: '',
    query: '',
    chips: [],
    advanced: false,
    problems: [],
    ...over,
  }
}

describe('the inventory for a filter given as text', () => {
  beforeEach(() => {
    api.parse.mockReset()
    api.post.mockReset()
  })

  it('sends the checked document to /assets/search, with the default attribution and the tab', async () => {
    api.parse
      .mockResolvedValueOnce(result({ text: 'port=22 OR port=23', document: doc }))
      .mockResolvedValueOnce(result({ text: 'type=ip_address attribution=approved' }))
      .mockResolvedValueOnce(result({ text: 'x', document: doc }))
    api.post.mockResolvedValue({ data: [], total: 0 })
    await fetchAdvancedAssets(
      '/api/v1/assets?type=ip_address&page=2&per_page=50&sort=-risk_score&with_triage=true&fq=port%3D22+OR+port%3D23'
    )
    expect(api.parse).toHaveBeenNthCalledWith(1, { entity: 'assets', text: 'port=22 OR port=23' })
    expect(api.parse).toHaveBeenNthCalledWith(2, {
      entity: 'assets',
      params: 'type=ip_address&attribution=approved',
    })
    expect(api.parse).toHaveBeenNthCalledWith(3, {
      entity: 'assets',
      text: '(type=ip_address attribution=approved) (port=22 OR port=23)',
    })
    expect(api.post).toHaveBeenCalledWith('/api/v1/assets/search', {
      ...doc,
      sort: ['-risk_score'],
      page: { page: 2, per_page: 50 },
    })
  })

  it('leaves the default attribution out when the text decides attribution itself', async () => {
    api.parse
      .mockResolvedValueOnce(
        result({
          text: 'attribution:rejected',
          document: { v: 1, filter: { field: 'attribution', op: 'in', value: ['rejected'] } },
        })
      )
      .mockResolvedValueOnce(result({ text: 'x', document: doc }))
    api.post.mockResolvedValue({ data: [] })
    await fetchAdvancedAssets('/api/v1/assets?fq=attribution%3Arejected')
    expect(api.parse).toHaveBeenNthCalledWith(2, { entity: 'assets', text: 'attribution:rejected' })
  })

  it('refuses rather than widening: an invalid text runs nothing', async () => {
    api.parse.mockResolvedValue(
      result({
        valid: false,
        problems: [{ code: 'unknown_field', message: '', start: 0, end: 1, line: 1, column: 1 }],
      })
    )
    await expect(fetchAdvancedAssets('/api/v1/assets?fq=foo%3Dbar')).rejects.toThrow()
    expect(api.post).not.toHaveBeenCalled()
  })

  it('gives a saved view the document, never the text', async () => {
    api.parse
      .mockResolvedValueOnce(result({ text: 'a', document: doc }))
      .mockResolvedValueOnce(result({ text: 'attribution=approved' }))
      .mockResolvedValueOnce(result({ text: 'x', document: doc }))
    await expect(advancedAssetsDocument('/api/v1/assets?fq=a')).resolves.toEqual(doc)
    expect(api.post).not.toHaveBeenCalled()
  })
})
