import { describe, expect, it } from 'vitest'

import {
  DEFAULT_SCAN_CONFIG_SORT,
  SCAN_CONFIG_SORT_FIELDS,
  parsePageSize,
  parseSortParam,
  toSortParam,
} from '../scans-url'

const F = SCAN_CONFIG_SORT_FIELDS
const D = DEFAULT_SCAN_CONFIG_SORT

describe('scans url codec', () => {
  it('reads a whitelisted sort in either direction', () => {
    expect(parseSortParam('-last_run_at', F, D)).toEqual([{ id: 'last_run_at', desc: true }])
    expect(parseSortParam('total_runs', F, D)).toEqual([{ id: 'total_runs', desc: false }])
  })

  it('falls back to the default for anything the API would refuse', () => {
    for (const raw of [
      null,
      '',
      'status',
      '-success_rate',
      'name,created_at',
      '--name',
      'name;drop',
    ]) {
      expect(parseSortParam(raw, F, D)).toEqual([{ id: 'name', desc: false }])
    }
  })

  it('round-trips sorting through the param', () => {
    for (const raw of ['name', '-name', '-created_at', 'next_run_at', '-total_runs']) {
      expect(toSortParam(parseSortParam(raw, F, D), F, D)).toBe(raw)
    }
  })

  it('returns to the default sort when a column is unsorted', () => {
    expect(toSortParam([], F, D)).toBe('name')
    expect(toSortParam([{ id: 'success_rate', desc: true }], F, D)).toBe('name')
  })

  it('snaps page sizes to the offered sizes', () => {
    expect(parsePageSize(50)).toBe(50)
    expect(parsePageSize(100)).toBe(100)
    expect(parsePageSize(10)).toBe(25)
    expect(parsePageSize(100000)).toBe(25)
  })
})
