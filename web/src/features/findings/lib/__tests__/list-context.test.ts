import { describe, expect, it } from 'vitest'
import {
  listQuery,
  locate,
  mergePage,
  parseListContext,
  readListContext,
  writeListContext,
  type FindingListContext,
} from '../list-context'

const id = (n: number) => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`
const ctx = (over: Partial<FindingListContext> = {}): FindingListContext => ({
  query: 'status=new&sort=-priority',
  label: 'Open P0 and P1',
  returnPath: '/findings?priority_class=P0,P1',
  ids: [id(21), id(22), id(23)],
  offset: 20,
  perPage: 20,
  total: 31,
  ...over,
})

function memStore() {
  const m = new Map<string, string>()
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    m,
  }
}

describe('listQuery', () => {
  it('keeps filters and sort, drops paging and odd params', () => {
    expect(listQuery('/api/v1/findings?status=new&page=3&per_page=50&Bad=1&sort=-rank')).toBe(
      'status=new&sort=-rank'
    )
    expect(listQuery('')).toBe('')
  })
})

describe('parseListContext', () => {
  it('refuses an open redirect in the return path', () => {
    for (const p of [
      'https://evil.example/findings',
      '//evil.example',
      '/findings/../admin',
      '/settings',
    ]) {
      expect(parseListContext({ ...ctx(), returnPath: p })?.returnPath).toBe('/findings')
    }
  })

  it('drops ids that are not ids and caps the label', () => {
    const c = parseListContext({
      ...ctx(),
      ids: [id(1), '<script>', id(2)],
      label: 'x'.repeat(500),
    })
    expect(c?.ids).toEqual([id(1), id(2)])
    expect(c?.label).toHaveLength(120)
  })

  it('is no context when malformed', () => {
    expect(parseListContext('not json')).toBeNull()
    expect(parseListContext({ ...ctx(), ids: [] })).toBeNull()
    expect(parseListContext({ ...ctx(), perPage: 0 })).toBeNull()
  })

  it('round-trips through storage', () => {
    const s = memStore()
    writeListContext(ctx(), s)
    expect(readListContext(s)).toEqual(ctx())
  })
})

describe('locate', () => {
  it('gives the position and the neighbours', () => {
    expect(locate(ctx(), id(22))).toEqual({ index: 21, prevId: id(21), nextId: id(23) })
  })

  it('asks for the neighbouring pages at the edges', () => {
    expect(locate(ctx(), id(21))?.loadPage).toEqual({ before: 1 })
    expect(locate(ctx(), id(23))?.loadPage).toEqual({ after: 2 })
  })

  it('does not ask past the ends of the list', () => {
    const c = ctx({ ids: [id(1), id(2)], offset: 0, total: 2 })
    expect(locate(c, id(1))?.loadPage).toBeUndefined()
    expect(locate(c, id(2))?.loadPage).toBeUndefined()
  })

  it('is null for a finding not in the list', () => {
    expect(locate(ctx(), id(99))).toBeNull()
  })
})

describe('mergePage', () => {
  it('appends the next page and prepends the previous one', () => {
    const c = ctx({ ids: [id(21), id(22)], offset: 20, perPage: 2, total: 31 })
    const after = mergePage(c, 12, [id(23), id(24)], 31)
    expect(after.ids).toEqual([id(21), id(22), id(23), id(24)])
    const before = mergePage(c, 10, [id(19), id(20)], 31)
    expect(before.ids).toEqual([id(19), id(20), id(21), id(22)])
    expect(before.offset).toBe(18)
  })

  it('ignores a page that does not touch the known ids', () => {
    const c = ctx({ ids: [id(21), id(22)], offset: 20, perPage: 2 })
    expect(mergePage(c, 15, [id(29), id(30)], 31)).toBe(c)
  })
})
