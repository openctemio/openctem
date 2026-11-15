import { describe, expect, it } from 'vitest'
import { findingsEmptyKind, type FindingsEmptyInput } from '../empty-kind'

const base: FindingsEmptyInput = {
  orgTotal: 0,
  filterCount: 0,
  hasSearch: false,
  hasContextScope: false,
  forbidden: false,
}

describe('findingsEmptyKind', () => {
  it('an organization with no findings and nothing narrowing the list has nothing yet', () => {
    expect(findingsEmptyKind(base)).toBe('nothing')
  })

  it('filters, a search or a context scope make it a no-match, never "nothing yet"', () => {
    expect(findingsEmptyKind({ ...base, filterCount: 2 })).toBe('no_match')
    expect(findingsEmptyKind({ ...base, hasSearch: true })).toBe('no_match')
    expect(findingsEmptyKind({ ...base, hasContextScope: true })).toBe('no_match')
  })

  it('findings that exist but are hidden are a no-match', () => {
    expect(findingsEmptyKind({ ...base, orgTotal: 1204, filterCount: 2, hasSearch: true })).toBe(
      'no_match'
    )
    expect(findingsEmptyKind({ ...base, orgTotal: 12 })).toBe('no_match')
  })

  it('an unknown total never claims the organization is empty', () => {
    expect(findingsEmptyKind({ ...base, orgTotal: undefined })).toBe('no_match')
  })

  it('a refused read is no-access whatever else is set', () => {
    expect(findingsEmptyKind({ ...base, forbidden: true })).toBe('no_access')
    expect(findingsEmptyKind({ ...base, forbidden: true, orgTotal: 5, filterCount: 3 })).toBe(
      'no_access'
    )
  })

  it('a practice with no findings in any state, nothing narrowing it, is its first run', () => {
    expect(findingsEmptyKind({ ...base, orgTotal: 40, practiceTotal: 0 })).toBe('practice_nothing')
  })

  it('a practice that has findings, filtered or hidden by the state to zero, is a no-match', () => {
    expect(findingsEmptyKind({ ...base, orgTotal: 40, practiceTotal: 7 })).toBe('no_match')
    expect(findingsEmptyKind({ ...base, orgTotal: 40, practiceTotal: 0, filterCount: 1 })).toBe(
      'no_match'
    )
    expect(findingsEmptyKind({ ...base, orgTotal: 40, practiceTotal: 0, hasSearch: true })).toBe(
      'no_match'
    )
  })

  it('an unknown practice total never claims the practice is empty', () => {
    expect(findingsEmptyKind({ ...base, orgTotal: 40, practiceTotal: undefined })).toBe('no_match')
  })

  it('an empty organization stays "nothing yet" whatever the practice', () => {
    expect(findingsEmptyKind({ ...base, orgTotal: 0, practiceTotal: 0 })).toBe('nothing')
  })
})
