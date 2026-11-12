import { describe, expect, it } from 'vitest'
import {
  applyCompletion,
  applyFix,
  contextAt,
  fieldCompletions,
  formatCount,
  localValues,
  quoteValue,
} from '../lib/complete'
import type { QuerySchemaField } from '../api/query-api'

const fields: QuerySchemaField[] = [
  {
    path: 'severity',
    type: 'enum',
    operators: ['=', '!=', 'in', 'not in'],
    enum: ['critical', 'high', 'medium', 'low', 'info'],
  },
  { path: 'is_in_kev', type: 'boolean', operators: ['=', '!='] },
  { path: 'tool_name', type: 'string', operators: ['=', '!=', 'in', 'not in'] },
  { path: 'last_seen_at', type: 'date-time', operators: ['>', '>=', '<', '<='] },
  { path: 'asset.domain', type: 'string', operators: ['=', 'in'] },
]

describe('contextAt', () => {
  it('reads a field name, a value and a list value at the caret', () => {
    expect(contextAt('kev=true sev', 12)).toMatchObject({
      kind: 'field',
      prefix: 'sev',
      start: 9,
      rest: 'kev=true',
    })
    expect(contextAt('-sev', 4)).toMatchObject({ kind: 'field', prefix: 'sev', start: 1 })
    expect(contextAt('severity>=hi', 12)).toMatchObject({
      kind: 'value',
      path: 'severity',
      op: '>=',
      prefix: 'hi',
      start: 10,
    })
    expect(contextAt('tool:nuclei,tri kev=true', 15)).toMatchObject({
      kind: 'value',
      path: 'tool',
      prefix: 'tri',
      start: 12,
      rest: 'kev=true',
    })
    expect(contextAt('(asset.domain=ex', 16)).toMatchObject({
      kind: 'value',
      path: 'asset.domain',
      prefix: 'ex',
    })
  })
  it('offers nothing inside a quoted value or after odd text', () => {
    expect(contextAt('title~"sql in', 13).kind).toBe('none')
    expect(contextAt('10.0.0.0/8', 10).kind).toBe('none')
  })
})

describe('completions', () => {
  it('lists fields, then operators for an exact field, and keywords', () => {
    expect(fieldCompletions(contextAt('sev', 3), fields).map((c) => c.label)).toEqual(['severity'])
    expect(fieldCompletions(contextAt('severity', 8), fields).map((c) => c.label)).toEqual([
      'severity=',
      'severity!=',
      'severity>=',
      'severity<=',
    ])
    expect(fieldCompletions(contextAt('o', 1), fields).map((c) => c.label)).toContain('OR')
    expect(fieldCompletions(contextAt('domain', 6), fields).map((c) => c.label)).toEqual([
      'asset.domain',
    ])
  })
  it('knows enum, boolean and time values; other fields ask the server', () => {
    const ctx = contextAt('severity=c', 10)
    expect(localValues(fields[0], ctx)?.map((c) => c.label)).toEqual(['critical'])
    expect(localValues(fields[1], contextAt('is_in_kev=', 10))?.map((c) => c.label)).toEqual([
      'true',
      'false',
    ])
    expect(localValues(fields[3], contextAt('last_seen_at<', 13))?.map((c) => c.label)).toEqual([
      '1d',
      '7d',
      '30d',
      '90d',
    ])
    expect(localValues(fields[2], contextAt('tool_name=n', 11))).toBeNull()
  })
  it('applies a completion and a fix in place', () => {
    const text = 'kev=true sev status:new'
    const ctx = contextAt(text, 12)
    expect(applyCompletion(text, ctx, 'severity')).toEqual({
      text: 'kev=true severity status:new',
      caret: 17,
    })
    expect(applyFix('severty=high', 0, 7, 'severity')).toBe('severity=high')
  })
  it('quotes values that would not read back as one value', () => {
    expect(quoteValue('nuclei')).toBe('nuclei')
    expect(quoteValue('two words')).toBe('"two words"')
    expect(quoteValue('-x')).toBe('"-x"')
    expect(quoteValue('a"b')).toBe('"a\\"b"')
  })
  it('caps counts at 10,000', () => {
    expect(formatCount(9999, 'en')).toBe('9,999')
    expect(formatCount(10000, 'en')).toBe('10,000')
    expect(formatCount(10001, 'en')).toBe('10,000+')
  })
})
