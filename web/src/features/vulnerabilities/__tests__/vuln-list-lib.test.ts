import { describe, expect, it } from 'vitest'
import {
  activeFilterCount,
  buildVulnListQuery,
  headlineFixVersion,
  kevDueDays,
  readSort,
  remediationState,
  rowFindingsHref,
  sortingToSort,
  sortToSorting,
} from '../lib/vuln-list'

const q = (s: string) => new URLSearchParams(s)

describe('buildVulnListQuery', () => {
  it('defaults to the Open lens, the risk order and the first page', () => {
    expect(buildVulnListQuery(q('')).toString()).toBe('state=open&page=1&per_page=25')
  })

  it('forwards only known params in their shape', () => {
    const got = buildVulnListQuery(
      q(
        'severity=critical,bogus&priority_class=P0,P9&kev=true&exploit=maybe&epss_gte=0.1&' +
          'q=%20log4j%20&sort=-epss&page=3&per_page=50&evil=1&asset_group_id=not-a-uuid&state=weird'
      )
    )
    expect(Object.fromEntries(got)).toEqual({
      state: 'open',
      severity: 'critical',
      priority_class: 'P0',
      kev: 'true',
      epss_gte: '0.1',
      q: 'log4j',
      sort: '-epss',
      page: '3',
      per_page: '50',
    })
  })

  it('keeps a valid asset group and a false flag, drops an off-list EPSS and page size', () => {
    const id = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'
    const got = buildVulnListQuery(q(`asset_group_id=${id}&has_fix=false&epss_gte=0.33&per_page=7`))
    expect(got.get('asset_group_id')).toBe(id)
    expect(got.get('has_fix')).toBe('false')
    expect(got.get('epss_gte')).toBeNull()
    expect(got.get('per_page')).toBe('25')
  })

  it('caps the search text', () => {
    expect(buildVulnListQuery(q(`q=${'a'.repeat(300)}`)).get('q')).toHaveLength(200)
  })
})

describe('sort mapping', () => {
  it('risk has no column and cannot be flipped', () => {
    expect(readSort(q('sort=-risk'))).toEqual({ key: 'risk', flipped: false })
    expect(sortToSorting({ key: 'risk', flipped: false })).toEqual([])
    expect(sortingToSort([])).toBe('')
  })

  it('round-trips columns with their natural direction', () => {
    for (const s of ['epss', '-epss', 'cve', '-cve', 'kev_due', '-last_seen']) {
      expect(sortingToSort(sortToSorting(readSort(q(`sort=${s}`))))).toBe(s)
    }
    expect(sortToSorting(readSort(q('sort=epss')))).toEqual([{ id: 'epss', desc: true }])
    expect(sortToSorting(readSort(q('sort=cve')))).toEqual([{ id: 'cve', desc: false }])
  })

  it('an unknown sort falls back to risk', () => {
    expect(readSort(q('sort=title'))).toEqual({ key: 'risk', flipped: false })
  })
})

describe('row helpers', () => {
  it('counts the facet filters, not search, sort or lens', () => {
    expect(
      activeFilterCount(q('severity=critical,high&kev=true&epss_gte=0.5&q=x&sort=cve&state=all'))
    ).toBe(4)
  })

  it('days to the KEV due date', () => {
    const now = Date.parse('2026-10-27T12:00:00Z')
    expect(kevDueDays('2026-11-01T00:00:00Z', now)).toBe(4)
    expect(kevDueDays('2026-10-20T00:00:00Z', now)).toBeLessThan(0)
    expect(kevDueDays(undefined, now)).toBeUndefined()
    expect(kevDueDays('not a date', now)).toBeUndefined()
  })

  it('remediation state', () => {
    expect(remediationState({ open_findings: 0, in_task: 0 })).toBe('closed')
    expect(remediationState({ open_findings: 3, in_task: 0 })).toBe('untracked')
    expect(remediationState({ open_findings: 3, in_task: 1 })).toBe('partial')
    expect(remediationState({ open_findings: 3, in_task: 3 })).toBe('tracked')
  })

  it('the first non-empty fixed version', () => {
    expect(headlineFixVersion({ fixed_versions: ['', '2.4.7', '3.0'] })).toBe('2.4.7')
    expect(headlineFixVersion({ fixed_versions: [] })).toBeUndefined()
  })

  it('a row opens the findings list with the same filters', () => {
    expect(
      rowFindingsHref('CVE-2024-3094', q('severity=high&kev=true&state=all'), { group: 'asset_id' })
    ).toBe('/findings?cve_id=CVE-2024-3094&state=all&severity=high&group=asset_id')
  })
})
