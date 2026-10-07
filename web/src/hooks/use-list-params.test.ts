import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, beforeEach } from 'vitest'

import { parseListSort, useListParams } from './use-list-params'

function setUrl(search: string) {
  window.history.replaceState(null, '', `/scans/runs${search}`)
}

const OPTIONS = {
  pageSizes: [25, 50, 100],
  defaultPageSize: 25,
  sortFields: ['created_at', 'started_at'],
  defaultSort: '-created_at',
  filters: { status: '', scan_id: '' },
} as const

describe('useListParams', () => {
  beforeEach(() => setUrl(''))

  it('reads the default view from a clean URL', () => {
    const { result } = renderHook(() => useListParams(OPTIONS))
    expect(result.current.page).toBe(1)
    expect(result.current.perPage).toBe(25)
    expect(result.current.sort).toBe('-created_at')
    expect(result.current.apiParams).toEqual({ page: 1, per_page: 25, sort: '-created_at' })
  })

  it('reads page, per_page, sort, q and filters from a link', () => {
    setUrl('?page=3&per_page=50&sort=started_at&q=acme&status=failed&scan_id=s1')
    const { result } = renderHook(() => useListParams(OPTIONS))
    expect(result.current.pagination).toEqual({ pageIndex: 2, pageSize: 50 })
    expect(result.current.sorting).toEqual([{ id: 'started_at', desc: false }])
    expect(result.current.apiParams).toEqual({
      page: 3,
      per_page: 50,
      sort: 'started_at',
      q: 'acme',
      status: 'failed',
      scan_id: 's1',
    })
  })

  // A hand-edited or stale link falls back; nothing the API refuses is sent.
  it.each([
    ['?page=0', 'page', 1],
    ['?page=2.5', 'page', 1],
    ['?page=0x10', 'page', 1],
    ['?per_page=1000', 'perPage', 25],
    ['?sort=password', 'sort', '-created_at'],
    ['?sort=created_at,started_at', 'sort', '-created_at'],
  ])('%s falls back for %s', (search, key, want) => {
    setUrl(search)
    const { result } = renderHook(() => useListParams(OPTIONS))
    expect(result.current[key as 'page' | 'perPage' | 'sort']).toBe(want)
  })

  it('a filter, search or page-size change goes back to page 1', () => {
    setUrl('?page=4')
    const { result } = renderHook(() => useListParams(OPTIONS))
    act(() => result.current.setFilter('status', 'failed'))
    expect(window.location.search).toBe('?status=failed')
    act(() => result.current.setPage(3))
    act(() => result.current.setSearch('  acme '))
    expect(new URLSearchParams(window.location.search).get('page')).toBeNull()
    expect(new URLSearchParams(window.location.search).get('q')).toBe('  acme ')
    expect(result.current.apiParams.q).toBe('acme')
    act(() => result.current.setPage(2))
    act(() => result.current.setPagination({ pageIndex: 1, pageSize: 100 }))
    const params = new URLSearchParams(window.location.search)
    expect(params.get('per_page')).toBe('100')
    expect(params.get('page')).toBeNull()
  })

  it('pages with plain names and leaves defaults out of the URL', () => {
    const { result } = renderHook(() => useListParams(OPTIONS))
    act(() => result.current.setPagination({ pageIndex: 1, pageSize: 25 }))
    expect(window.location.search).toBe('?page=2')
    act(() => result.current.setPagination({ pageIndex: 0, pageSize: 25 }))
    expect(window.location.search).toBe('')
  })

  it('sorting writes sort and returns to page 1; unsorting restores the default', () => {
    setUrl('?page=2')
    const { result } = renderHook(() => useListParams(OPTIONS))
    act(() => result.current.setSorting([{ id: 'started_at', desc: true }]))
    expect(window.location.search).toBe('?sort=-started_at')
    act(() => result.current.setSorting([]))
    expect(window.location.search).toBe('')
  })

  it('reset clears the search and filters only', () => {
    setUrl('?q=x&status=failed&per_page=50&page=2')
    const { result } = renderHook(() => useListParams(OPTIONS))
    act(() => result.current.reset())
    expect(window.location.search).toBe('?per_page=50')
  })

  it('keeps unrelated parameters (an open sheet, a tab)', () => {
    setUrl('?run=r1')
    const { result } = renderHook(() => useListParams(OPTIONS))
    act(() => result.current.setFilter('status', 'failed'))
    expect(window.location.search).toBe('?run=r1&status=failed')
  })
})

describe('parseListSort', () => {
  it('accepts an allowed field in either direction', () => {
    expect(parseListSort('-created_at', ['created_at'])).toBe('-created_at')
    expect(parseListSort('created_at', ['created_at'])).toBe('created_at')
  })
  it('refuses anything the API would refuse', () => {
    for (const raw of ['status', '-success_rate', 'name,created_at', '--name', 'name;drop']) {
      expect(parseListSort(raw, ['name', 'created_at'])).toBeNull()
    }
  })
  it('refuses unknown fields, lists and empty values', () => {
    expect(parseListSort('name', ['created_at'])).toBeNull()
    expect(parseListSort('a,b', ['a', 'b'])).toBeNull()
    expect(parseListSort('', ['a'])).toBeNull()
    expect(parseListSort(null, ['a'])).toBeNull()
  })
})
