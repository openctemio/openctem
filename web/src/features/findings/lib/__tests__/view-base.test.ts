import { describe, expect, it } from 'vitest'
import { ALL_FINDINGS_PARAMS, baseViewSearch, deriveBaseView } from '../view-base'
import type { QuickView } from '../quick-views'

const view = (key: string, params: string): QuickView => ({ key, count: 1, params })
const VIEWS = [
  view('active', 'state=open'),
  view('needs_triage', 'status=new'),
  view('my_queue', 'state=open&related_to=me'),
  view('sla_breached', 'state=open&sla_status=overdue,exceeded'),
  view('pending_approval', 'pending_approval=true'),
  view('closed', 'state=closed'),
]

const name = (search: string, extra: Partial<Parameters<typeof deriveBaseView>[0]> = {}) => {
  const base = deriveBaseView({ search, views: VIEWS, ...extra })
  return `${base.kind === 'quick' ? base.view.key : base.kind}${base.modified ? ' modified' : ''}`
}

describe('deriveBaseView', () => {
  const cases: Array<[string, string, string]> = [
    ['no params is the default Active lens', '', 'active'],
    ['the exact quick view', 'status=new&state=all', 'needs_triage'],
    [
      'page, sort, grouping and the search mode do not change it',
      'page=2&sort=-id&mode=query',
      'active',
    ],
    ['the practice is the scope, not a change', 'practice=compliance', 'active'],
    ['Active plus a filter is Active, modified', 'severity=critical', 'active modified'],
    ['explicit state plus a filter', 'state=open&is_in_kev=true', 'active modified'],
    ['search text marks the view modified', 'q=login', 'active modified'],
    [
      'a quick view plus a filter keeps that view',
      'status=new&state=all&severity=high',
      'needs_triage modified',
    ],
    [
      'the most specific base wins over Active',
      'state=open&related_to=me&severity=low',
      'my_queue modified',
    ],
    [
      'a changed value of the view is no longer that view',
      'state=open&sla_status=overdue',
      'active modified',
    ],
    ['Closed plus a filter', 'state=closed&source=pentest', 'closed modified'],
    ['every state and nothing else is All findings', 'state=all', 'all'],
    ['All findings with search text', 'state=all&q=x', 'all modified'],
    ['no view holds: All findings, modified', 'state=all&severity=high', 'all modified'],
    ['another lens with no view of its own', 'state=fixed', 'all modified'],
    [
      'an explicit informational choice is a change',
      'state=all&informational=false',
      'all modified',
    ],
  ]
  it.each(cases)('%s', (_n, search, want) => {
    expect(name(search)).toBe(want)
  })

  it('an open saved view is the view, modified only with unsaved changes', () => {
    expect(name('view=abc', { savedView: true })).toBe('saved')
    expect(name('view=abc&severity=high', { savedView: true, savedViewChanged: true })).toBe(
      'saved modified'
    )
  })

  it('never has no view: without quick views the list is All findings', () => {
    expect(deriveBaseView({ search: 'severity=high', views: [] })).toEqual({
      kind: 'all',
      modified: true,
    })
  })
})

describe('baseViewSearch', () => {
  it('is the quick view link, keeping the practice', () => {
    const base = deriveBaseView({ search: 'status=new&state=all&severity=high', views: VIEWS })
    if (base.kind === 'saved') throw new Error('unexpected')
    expect(
      baseViewSearch(base, 'status=new&state=all&severity=high&practice=secrets&q=x').toString()
    ).toBe('status=new&state=all&practice=secrets')
  })

  it('is every state for All findings', () => {
    expect(baseViewSearch({ kind: 'all', modified: true }, 'state=fixed&q=x').toString()).toBe(
      ALL_FINDINGS_PARAMS
    )
  })

  it('resets to exactly the view it names', () => {
    for (const search of ['severity=critical', 'state=closed&source=pentest', 'state=all&q=x']) {
      const base = deriveBaseView({ search, views: VIEWS })
      if (base.kind === 'saved') throw new Error('unexpected')
      const back = deriveBaseView({ search: baseViewSearch(base, search), views: VIEWS })
      expect(back).toEqual({ ...base, modified: false })
    }
  })
})
