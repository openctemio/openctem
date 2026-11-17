import { describe, expect, it } from 'vitest'
import { viewChanges, type ViewChange } from '../view-changes'
import type { ActiveFilter } from '@/features/findings/filters/model'

const locked = (param: string, values: string[]): ActiveFilter => ({
  param,
  field: param.replace(/_(not|gte|lte|gt|lt)$/, ''),
  op: 'in',
  values,
  locked: true,
})

const view = {
  filter: { v: 1, filter: { all: [] }, q: 'log4j', sort: ['-created_at'] },
  group_by: '',
  density: 'compact',
}
const base = ['severity', 'asset', 'status', 'slaStatus']

function changes(
  search: string,
  over: Partial<Parameters<typeof viewChanges>[0]> = {}
): ViewChange[] {
  return viewChanges({
    view,
    search: new URLSearchParams(search),
    viewFilters: [locked('severity', ['critical', 'high'])],
    baselineColumns: base,
    columns: base,
    density: undefined,
    ...over,
  })
}

const kinds = (c: ViewChange[]) => c.map((x) => x.kind)

describe('viewChanges (the unsaved-changes dot)', () => {
  const cases: Array<[string, string, Partial<Parameters<typeof viewChanges>[0]>, string[]]> = [
    ['the view as opened', 'view=abc', {}, []],
    ['paging is no change', 'view=abc&page=3&per_page=50', {}, []],
    ["the view's own filter repeated in the URL is no change", 'severity=critical,high', {}, []],
    ['the same values in another order are a change', 'severity=high,critical', {}, ['filters']],
    ['another value on a field the view sets', 'severity=low', {}, ['filters']],
    ['a filter added', 'epss_score_gte=0.5', {}, ['filters']],
    ['two filters added', 'epss_score_gte=0.5&is_in_kev=true', {}, ['filters']],
    [
      'query text applied on top of the view',
      'view=abc&mode=query&fq=a%3D1+OR+b%3D2',
      {},
      ['filters'],
    ],
    ['the search mode alone is no change', 'view=abc&mode=query', {}, []],
    ["the view's search text repeated", 'q=log4j', {}, []],
    ['another search text', 'q=struts', {}, ['search']],
    ["the view's sort repeated", 'sort=-created_at', {}, []],
    ['another sort', 'sort=severity', {}, ['sort']],
    ['a grouping the view does not have', 'group=cve_id', {}, ['group']],
    ['a column hidden', '', { columns: ['severity', 'asset', 'status'] }, ['columns']],
    ['the same columns', '', { columns: ['slaStatus', 'status', 'asset', 'severity'] }, []],
    ['a density the view does not have', '', { density: 'comfortable' }, ['density']],
    ["the view's own density", '', { density: 'compact' }, []],
    [
      'several at once',
      'epss_score_gte=0.5&sort=severity',
      { density: 'comfortable' },
      ['filters', 'sort', 'density'],
    ],
  ]
  for (const [name, search, over, want] of cases) {
    it(name, () => expect(kinds(changes(search, over))).toEqual(want))
  }

  it('counts query text on top of the view as one filter', () => {
    expect(changes('is_in_kev=true&fq=severity%3Dlow+OR+epss%3E%3D0.5')).toEqual([
      { kind: 'filters', count: 2 },
    ])
  })

  it('a query text applied in place of the view is one change, whatever params it wrote', () => {
    expect(
      changes('from_view=abc&mode=query&fq=a%3D1+OR+b%3D2&state=all&practice=all&q=x', {
        queryText: true,
      })
    ).toEqual([{ kind: 'query' }])
    expect(
      kinds(changes('from_view=abc&is_in_kev=true&sort=severity', { queryText: true }))
    ).toEqual(['query', 'sort'])
    // Even a text that says exactly the view's flat filter: the URL no longer opens the view.
    expect(kinds(changes('from_view=abc&severity=critical,high', { queryText: true }))).toEqual([
      'query',
    ])
  })

  it('counts the filters added', () => {
    expect(changes('epss_score_gte=0.5&is_in_kev=true&severity=critical,high')).toEqual([
      { kind: 'filters', count: 2 },
    ])
  })

  it('a view with no saved density treats any chosen density as a change', () => {
    expect(
      kinds(changes('', { view: { ...view, density: undefined }, density: 'compact' }))
    ).toEqual(['density'])
  })

  it('a grouped view opened as saved is no change', () => {
    expect(kinds(changes('group=cve_id', { view: { ...view, group_by: 'cve_id' } }))).toEqual([])
  })
})
