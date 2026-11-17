import { describe, expect, it, vi, beforeEach } from 'vitest'
import { applyTextFilter, filterParams, FQ_PARAM } from '../filter-query-mode'
import { NON_FILTER_PARAMS } from '../model'
import { advancedFindingsDocument } from '../../api/advanced-fetch'
import { viewQueryFromSearch } from '@/features/saved-views/api/use-saved-views'
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

// Answers of POST /query/parse recorded from the server's printer and parser
// (internal/app/query Parse, findings entity) for the inputs named.
const RECORDED = {
  // params "severity=critical&state=open&practice_not=compliance"
  printed: result({
    text: 'practice!=compliance severity=critical state=open',
    params: { practice_not: 'compliance', severity: 'critical', state: 'open' },
  }),
  // text "practice=cloud kev=true log4j"
  onePractice: result({
    text: 'practice=cloud is_in_kev=true log4j',
    params: { is_in_kev: 'true', practice: 'cloud', q: 'log4j' },
  }),
  // text "practice:aspm,infra state=fixed": two practices, no switch value
  twoPractices: result({
    text: 'practice:aspm,infra state=fixed',
    params: { practice: 'aspm,infra', state: 'fixed' },
  }),
  // text "kev=true": no state, no practice
  kevOnly: result({ text: 'is_in_kev=true', params: { is_in_kev: 'true' } }),
  // text "(severity=critical OR kev=true) state=open"
  advanced: result({ text: '(severity=critical OR is_in_kev=true) state=open', advanced: true }),
}

describe('the findings Query mode and the URL', () => {
  it('reads the filter part of the URL, keeping page state and context out', () => {
    const s = new URLSearchParams(
      'severity=critical&q=log4j&page=3&sort=-severity&view=v1&asset_id=a1&fq=x&state=open&density=compact'
    )
    expect(filterParams(s, skip)).toBe('severity=critical&q=log4j&state=open')
  })

  it('adds the State lens and the Practice switch as the list applies them', () => {
    const s = new URLSearchParams('severity=critical&sort=-severity')
    expect(filterParams(s, skip, { state: 'open', practice_not: 'compliance' })).toBe(
      'severity=critical&state=open&practice_not=compliance'
    )
    // A lens in the URL is the one the list applies.
    expect(
      filterParams(new URLSearchParams('state=fixed'), skip, {
        state: 'open',
        practice_not: 'compliance',
      })
    ).toBe('state=fixed&practice_not=compliance')
  })

  it('round trip: the printed default view comes back as the same URL', () => {
    const s = new URLSearchParams('severity=critical&sort=-severity&asset_id=a1')
    const next = applyTextFilter(s, skip, RECORDED.printed)
    expect(next.get('severity')).toBe('critical')
    expect(next.get('state')).toBe('open')
    expect(next.get('practice')).toBe('vulnerabilities')
    expect(next.get('practice_not')).toBeNull()
    expect(next.get('sort')).toBe('-severity')
    expect(next.get('asset_id')).toBe('a1')
    expect(next.get(FQ_PARAM)).toBeNull()
  })

  it('one practice goes back to the Practice switch', () => {
    const next = applyTextFilter(
      new URLSearchParams('practice=vulnerabilities&state=open'),
      skip,
      RECORDED.onePractice
    )
    expect(next.get('practice')).toBe('cloud')
    expect(next.get('is_in_kev')).toBe('true')
    expect(next.get('q')).toBe('log4j')
    // The text left the state out: no state restriction.
    expect(next.get('state')).toBe('all')
  })

  it('what the text leaves out is not restricted (state and practice all)', () => {
    const next = applyTextFilter(new URLSearchParams('state=open'), skip, RECORDED.kevOnly)
    expect(next.toString()).toBe('is_in_kev=true&state=all&practice=all')
  })

  it('practices the switch cannot show keep the whole text as fq, never dropped', () => {
    const next = applyTextFilter(new URLSearchParams(''), skip, RECORDED.twoPractices)
    expect(next.get(FQ_PARAM)).toBe('practice:aspm,infra state=fixed')
    expect(next.get('state')).toBe('all')
    expect(next.get('practice')).toBe('all')
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
      'sort=-severity&asset_id=a1&severity=critical%2Chigh&is_in_kev=true&q=log4j&state=all&practice=all'
    )
  })

  it('keeps a filter chips cannot show as fq, never flattened', () => {
    const next = applyTextFilter(new URLSearchParams('severity=low'), skip, RECORDED.advanced)
    expect(next.get(FQ_PARAM)).toBe('(severity=critical OR is_in_kev=true) state=open')
    expect(next.get('severity')).toBeNull()
    expect(next.get('state')).toBe('all')
  })

  describe('with a saved view open', () => {
    const ID = '0b0e7a52-6c1f-4f0e-9d0a-1c2b3d4e5f60'
    const VIEW = `view=${ID}`

    it('an applied text drives the list alone: the view leaves the URL and stays as from_view', () => {
      const next = applyTextFilter(
        new URLSearchParams(`${VIEW}&mode=query&sort=-severity`),
        skip,
        RECORDED.advanced
      )
      // No double application: no request can send the view under the text.
      expect(next.get('view')).toBeNull()
      expect(next.get('from_view')).toBe(ID)
      expect(next.get(FQ_PARAM)).toBe('(severity=critical OR is_in_kev=true) state=open')
      expect(next.get('mode')).toBe('query')
      expect(next.get('sort')).toBe('-severity')
      // The text is the whole filter: what it leaves out is not restricted.
      expect(next.get('state')).toBe('all')
      expect(next.get('practice')).toBe('all')
    })

    it('a text chips can show is written as flat params, still without the view', () => {
      const next = applyTextFilter(new URLSearchParams(VIEW), skip, RECORDED.kevOnly)
      expect(next.toString()).toBe(`from_view=${ID}&is_in_kev=true&state=all&practice=all`)
    })

    it('the next text keeps the view it came from', () => {
      const first = applyTextFilter(new URLSearchParams(VIEW), skip, RECORDED.kevOnly)
      const next = applyTextFilter(first, skip, RECORDED.advanced)
      expect(next.get('from_view')).toBe(ID)
      expect(next.get('view')).toBeNull()
      expect(next.get('is_in_kev')).toBeNull()
    })

    it('from_view is page state: no chip, no unknown filter, not part of the text or of a saved query', () => {
      const next = applyTextFilter(new URLSearchParams(VIEW), skip, RECORDED.kevOnly)
      expect(NON_FILTER_PARAMS.has('from_view')).toBe(true)
      expect(filterParams(next, skip)).toBe('is_in_kev=true&state=all&practice=all')
      expect(viewQueryFromSearch(`?${next.toString()}`)).toBe('is_in_kev=true&state=all')
    })

    it('view=verify (the queue, not a saved view) is left alone', () => {
      const next = applyTextFilter(new URLSearchParams('view=verify'), skip, RECORDED.kevOnly)
      expect(next.get('view')).toBe('verify')
      expect(next.get('from_view')).toBeNull()
    })
  })

  describe('the document a view stores for a text filter', () => {
    it('is the checked document of the list URL, with its sort, asked once per part', async () => {
      const document = { v: 1, filter: { any: [] } }
      api.parse.mockImplementation((req: { params?: string; text?: string }) =>
        Promise.resolve(
          req.params !== undefined
            ? result({ text: 'state=all' })
            : result({ text: req.text ?? '', document })
        )
      )
      const doc = await advancedFindingsDocument(
        '/api/v1/findings?fq=a%3D1+OR+b%3D2&state=all&sort=-severity,created_at&page=2&per_page=50'
      )
      expect(doc).toEqual({ ...document, sort: ['-severity', 'created_at'] })
      expect(api.parse).toHaveBeenLastCalledWith({
        entity: 'findings',
        text: '(state=all) (a=1 OR b=2)',
      })
    })

    it('refuses a URL that still names a view: its conditions would apply twice', async () => {
      await expect(
        advancedFindingsDocument(
          '/api/v1/findings?fq=a%3D1&view=0b0e7a52-6c1f-4f0e-9d0a-1c2b3d4e5f60'
        )
      ).rejects.toThrow()
    })
  })

  it('an empty text clears the filter, state and practice included', () => {
    expect(
      applyTextFilter(new URLSearchParams('severity=low&sort=x'), skip, result({})).toString()
    ).toBe('sort=x&state=all&practice=all')
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
