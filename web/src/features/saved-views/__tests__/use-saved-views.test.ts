import { beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({ post: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  post: api.post,
  put: api.put,
}))

import {
  createSavedView,
  duplicateSavedView,
  savedViewId,
  updateSavedView,
  viewQueryFromSearch,
} from '../api/use-saved-views'

describe('the save request body', () => {
  beforeEach(() => {
    api.post.mockReset().mockResolvedValue({})
    api.put.mockReset().mockResolvedValue({})
  })
  const base = { page: 'findings' as const, name: 'V', query: 'severity=high' }

  it('creates a Basic mode view with no page_params key at all', async () => {
    await createSavedView({ ...base, page_params: { mode: 'basic' } })
    const body = api.post.mock.calls[0][1]
    expect(api.post.mock.calls[0][0]).toBe('/api/v1/views')
    expect('page_params' in body).toBe(false)
    expect(JSON.parse(JSON.stringify(body))).toEqual(base)
  })

  it('creates a Query mode view with page_params {mode: query}', async () => {
    await createSavedView({ ...base, page_params: { mode: 'query' } })
    expect(api.post.mock.calls[0][1].page_params).toEqual({ mode: 'query' })
  })

  it('sends no page_params for an empty object or none', async () => {
    await createSavedView({ ...base, page_params: {} })
    await createSavedView(base)
    for (const call of api.post.mock.calls) expect('page_params' in call[1]).toBe(false)
  })

  it('keeps other page params and drops only the default mode', async () => {
    await createSavedView({ ...base, page_params: { mode: 'basic', kev: 'true' } })
    expect(api.post.mock.calls[0][1].page_params).toEqual({ kev: 'true' })
  })

  it('updates a Basic mode view with no page_params, a Query mode view with the mode', async () => {
    await updateSavedView('abc', { ...base, page_params: { mode: 'basic' } })
    expect(api.put.mock.calls[0][0]).toBe('/api/v1/views/abc')
    expect('page_params' in api.put.mock.calls[0][1]).toBe(false)
    await updateSavedView('abc', { ...base, page_params: { mode: 'query' } })
    expect(api.put.mock.calls[1][1].page_params).toEqual({ mode: 'query' })
  })

  it('duplicates by id alone', async () => {
    await duplicateSavedView('abc')
    expect(api.post).toHaveBeenCalledWith('/api/v1/views', { from_view_id: 'abc' })
  })
})

describe('saved views helpers', () => {
  it('only a UUID is a saved view id (view=verify is page state)', () => {
    expect(savedViewId('verify')).toBeUndefined()
    expect(savedViewId('')).toBeUndefined()
    expect(savedViewId('0193e000-0000-7000-8000-000000000001')).toBe(
      '0193e000-0000-7000-8000-000000000001'
    )
  })
  it('keeps only the filter params', () => {
    expect(
      viewQueryFromSearch(
        '?severity=critical&page=3&per_page=50&view=verify&group=cve_id&q=log4j&sort=-created_at'
      )
    ).toBe('severity=critical&q=log4j&sort=-created_at')
    const id = '0193e000-0000-7000-8000-000000000001'
    expect(viewQueryFromSearch(`?view=${id}&severity=low`)).toBe(`view=${id}&severity=low`)
  })
  it('does not save where the person came from (a group drill-down or a task) as a condition', () => {
    expect(viewQueryFromSearch('?rule_id=github-pat&from=group:rule_id&severity=high')).toBe(
      'rule_id=github-pat&severity=high'
    )
    expect(viewQueryFromSearch('?from=task:0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b&q=x')).toBe('q=x')
  })
  it('keeps the search mode out of the filter (it is saved as a page param)', () => {
    expect(viewQueryFromSearch('?severity=high&mode=query')).toBe('severity=high')
  })
})
