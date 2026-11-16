import { describe, expect, it } from 'vitest'
import {
  applyCompletion,
  applyFix,
  contextAt,
  fieldByName,
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

describe('localProblem (checked while typing, no request)', () => {
  it('passes balanced text, quoted parentheses and escaped quotes', async () => {
    const { localProblem } = await import('../lib/complete')
    expect(localProblem('severity>=high (kev=true OR epss>0.5)')).toBeNull()
    expect(localProblem('title~"a (b" tool="x\\"y"')).toBeNull()
    expect(localProblem('practice!=compliance state=fixed')).toBeNull()
  })
  it('names an unclosed quote, an unclosed or an extra parenthesis with its place', async () => {
    const { localProblem } = await import('../lib/complete')
    expect(localProblem('tool="nuclei')).toEqual({ code: 'unclosed_quote', start: 5, end: 6 })
    expect(localProblem('(a=1 OR (b=2)')).toEqual({ code: 'unclosed_paren', start: 0, end: 1 })
    expect(localProblem('a=1)')).toEqual({ code: 'extra_paren', start: 3, end: 4 })
  })
})

// The schema's order and groups (common first, ids last), with short names.
const ranked: QuerySchemaField[] = [
  { path: 'severity', type: 'enum', operators: ['='], enum: ['high'], group: 'common' },
  { path: 'is_in_kev', type: 'boolean', operators: ['=', '!='], aliases: ['kev'], group: 'common' },
  { path: 'assigned_to', type: 'id', operators: ['='], aliases: ['assignee'], group: 'common' },
  {
    path: 'asset.domain',
    type: 'string',
    operators: ['='],
    aliases: ['domain', 'asset_domain'],
    group: 'common',
  },
  { path: 'asset.type', type: 'enum', operators: ['='], enum: ['host'], group: 'asset' },
  { path: 'informational', type: 'boolean', operators: ['='], group: 'more' },
  { path: 'asset_id', type: 'id', operators: ['='], group: 'identifier' },
  { path: 'id', type: 'id', operators: ['='], group: 'identifier' },
]

describe('field suggestions: order, short names, groups', () => {
  it('offers every field in the schema order under its group when nothing is typed', () => {
    const all = fieldCompletions(contextAt('severity=high ', 14), ranked)
    expect(all.map((c) => c.label)).toEqual([
      'severity',
      'kev',
      'assignee',
      'domain',
      'asset.type',
      'informational',
      'asset_id',
      'id',
    ])
    expect(all.map((c) => c.group)).toEqual([
      'common',
      'common',
      'common',
      'common',
      'asset',
      'more',
      'identifier',
      'identifier',
    ])
    // A row inserts the short name and carries its field (for its description).
    expect(all[1]).toMatchObject({ kind: 'field', insert: 'kev', field: ranked[1] })
  })
  it('puts prefix matches before substring matches, showing the name that matched', () => {
    expect(fieldCompletions(contextAt('a', 1), ranked).map((c) => c.label)).toEqual([
      'AND',
      'assignee',
      'asset.domain',
      'asset.type',
      'asset_id',
      'informational',
    ])
    // A former name still finds its field.
    expect(fieldCompletions(contextAt('asset_d', 7), ranked).map((c) => c.label)).toEqual([
      'asset_domain',
    ])
    // An identifier is offered when its name is typed.
    expect(fieldCompletions(contextAt('asset_i', 7), ranked).map((c) => c.label)).toEqual([
      'asset_id',
    ])
    expect(fieldCompletions(contextAt('ke', 2), ranked).map((c) => c.label)).toEqual(['kev'])
  })
  it('offers operators after a short name as after a path', () => {
    expect(fieldCompletions(contextAt('kev', 3), ranked).map((c) => c.label)).toEqual([
      'kev=',
      'kev!=',
    ])
    expect(fieldCompletions(contextAt('is_in_kev', 9), ranked).map((c) => c.label)).toEqual([
      'is_in_kev=',
      'is_in_kev!=',
    ])
  })
  it('resolves a short name to its field for values', () => {
    expect(fieldByName(ranked, 'kev')).toBe(ranked[1])
    expect(fieldByName(ranked, 'asset_domain')).toBe(ranked[3])
    expect(fieldByName(ranked, 'nope')).toBeUndefined()
    const ctx = contextAt('kev=t', 5)
    expect(localValues(fieldByName(ranked, ctx.path), ctx)?.map((c) => c.label)).toEqual(['true'])
  })
})
