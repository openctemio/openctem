import { describe, expect, it } from 'vitest'
import type { ParseResult } from '@/features/query/api/query-api'
import { applyScanTextFilter, SCAN_FQ_PARAM, scanFilterParams } from '../scan-query'

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

describe('the scans page and its query text', () => {
  it("reads the page's filters as the list's params, leaving page state out", () => {
    const s = new URLSearchParams(
      'status=active&type=workflow&schedule=all&origin=system&tag=prod&q=nightly&page=3&per_page=50&sort=-total_runs&one_off=1&fq=x'
    )
    expect(scanFilterParams(s)).toBe(
      'status=active&scan_type=workflow&origin=system&tag=prod&q=nightly'
    )
  })

  it('writes a filter the controls can show back as the page params, so links keep their form', () => {
    const next = applyScanTextFilter(
      new URLSearchParams('status=paused&page=3&sort=-total_runs&one_off=1&fq=old'),
      result({
        text: 'status=active scan_type=single tag:prod,edge nightly',
        params: { status: 'active', scan_type: 'single', tag: 'prod,edge', q: 'nightly' },
      })
    )
    expect(next.toString()).toBe(
      'sort=-total_runs&one_off=1&status=active&type=single&tag=prod%2Cedge&q=nightly'
    )
  })

  it('keeps a filter the controls cannot show as fq, never flattened', () => {
    const next = applyScanTextFilter(
      new URLSearchParams('status=paused&tag=prod&sort=name'),
      result({ text: 'status=active OR total_runs>=3', advanced: true })
    )
    expect(next.get(SCAN_FQ_PARAM)).toBe('status=active OR total_runs>=3')
    expect(next.get('status')).toBeNull()
    expect(next.get('tag')).toBeNull()
    expect(next.get('sort')).toBe('name')
  })

  it('keeps a field or a list the controls have no place for as fq', () => {
    const cases: Record<string, string>[] = [
      { total_runs_gte: '3' },
      { status: 'active,paused' },
      { status_not: 'active' },
    ]
    for (const params of cases) {
      const next = applyScanTextFilter(new URLSearchParams(), result({ text: 'x', params }))
      expect(next.get(SCAN_FQ_PARAM)).toBe('x')
    }
  })

  it('an empty text clears the filter and the page', () => {
    expect(
      applyScanTextFilter(
        new URLSearchParams('status=paused&fq=x&page=2&sort=name'),
        result({})
      ).toString()
    ).toBe('sort=name')
  })
})
