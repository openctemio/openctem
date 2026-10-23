import { describe, expect, it } from 'vitest'
import {
  OPTIONAL_COLUMNS,
  columnsToSave,
  defaultColumns,
  normalizeColumns,
  parseColumnsParam,
  sameColumns,
  serializeColumns,
  visibilityOf,
  visibleFrom,
} from '../list-columns'

describe('default columns', () => {
  it('Active leaves severity out (priority already carries it); every other view shows it', () => {
    expect(defaultColumns(true)).toEqual(['asset', 'status', 'slaStatus'])
    expect(defaultColumns(false)).toEqual(['severity', 'asset', 'status', 'slaStatus'])
  })

  it('the scanner and the first-seen date start hidden', () => {
    for (const active of [true, false]) {
      expect(defaultColumns(active)).not.toContain('source')
      expect(defaultColumns(active)).not.toContain('createdAt')
    }
  })
})

describe('normalizeColumns / parseColumnsParam', () => {
  it('keeps table order and drops anything that is not an optional column', () => {
    expect(normalizeColumns(['status', 'title', 'severity', 'nope', 'priorityClass'])).toEqual([
      'severity',
      'status',
    ])
  })

  it('reads the URL param; absent is undefined; empty is "none"', () => {
    expect(parseColumnsParam(null)).toBeUndefined()
    expect(parseColumnsParam('status,severity')).toEqual(['severity', 'status'])
    expect(parseColumnsParam('')).toEqual([])
    expect(parseColumnsParam('title,<script>')).toEqual([])
  })

  it('round-trips', () => {
    const cols = normalizeColumns(['createdAt', 'asset'])
    expect(parseColumnsParam(serializeColumns(cols))).toEqual(cols)
  })
})

describe('sameColumns', () => {
  it('compares sets in table order', () => {
    expect(sameColumns(['status', 'severity'], ['severity', 'status'])).toBe(true)
    expect(sameColumns(['severity'], ['severity', 'status'])).toBe(false)
    expect(sameColumns(['title', 'severity'], ['severity'])).toBe(true)
  })
})

describe('visibility', () => {
  it('turns a list into a visibility map for every optional column', () => {
    const map = visibilityOf(['asset', 'status'])
    expect(Object.keys(map)).toEqual([...OPTIONAL_COLUMNS])
    expect(map).toMatchObject({ asset: true, status: true, severity: false, source: false })
  })

  it('reads it back; a column absent from the map counts as shown', () => {
    expect(visibleFrom({ severity: false, asset: true, source: false })).toEqual([
      'asset',
      'status',
      'slaStatus',
      'createdAt',
    ])
  })

  it('round-trips', () => {
    const cols = ['severity', 'slaStatus'] as const
    expect(visibleFrom(visibilityOf(cols))).toEqual([...cols])
  })
})

describe('columnsToSave', () => {
  it('always saves Finding and Priority first', () => {
    expect(columnsToSave(['status', 'asset'])).toEqual([
      'title',
      'priorityClass',
      'asset',
      'status',
    ])
    expect(columnsToSave([])).toEqual(['title', 'priorityClass'])
  })

  it('every saved id is a legal column name for the API', () => {
    for (const id of columnsToSave([...OPTIONAL_COLUMNS]))
      expect(id).toMatch(/^[A-Za-z0-9_]{1,64}$/)
  })
})
