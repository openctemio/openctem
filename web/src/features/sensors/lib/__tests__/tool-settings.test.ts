import { describe, expect, it } from 'vitest'

import {
  changeSummaryList,
  changedFields,
  draftFromValues,
  fieldMatches,
  isChangedValue,
  problemKey,
  toolSettingFields,
  valuesFromDraft,
  type ToolSettingField,
} from '../tool-settings'

const schema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    scan_strategy: {
      type: 'string',
      enum: ['auto', 'host-spray'],
      default: 'auto',
      'x-octm-group': 'Engine',
      'x-octm-flag': '-ss',
    },
    retries: { type: 'integer', minimum: 0, maximum: 10, 'x-octm-common': 'retries' },
    rate_limit: {
      type: 'integer',
      minimum: 1,
      maximum: 5000,
      default: 150,
      'x-octm-common': 'rate',
      'x-octm-flag': '-rate-limit',
      'x-octm-scope': 'scan',
    },
    headless: { type: 'boolean', default: false, 'x-octm-tier': 'T2', 'x-octm-flag': 'rm -rf' },
    api_token: { type: 'string', 'x-octm-sensitive': true },
    severity: { type: 'array', items: { type: 'string', enum: ['low', 'high'] } },
    dns: {
      type: 'object',
      title: 'DNS',
      properties: { resolvers: { type: 'array', items: { type: 'string' } } },
    },
    weird: { type: 'object' },
  },
}

describe('toolSettingFields', () => {
  it('puts common options first in their fixed order, then the tool options by group', () => {
    const keys = toolSettingFields(schema).map((f) => f.key)
    expect(keys.slice(0, 2)).toEqual(['rate_limit', 'retries'])
    expect(keys).toContain('dns.resolvers')
    expect(keys).not.toContain('api_token') // sensitive keys are never plain values
    expect(keys).not.toContain('weird')
  })

  it('reads bounds, enums, tiers and flags, and drops a flag that is not one token', () => {
    const byKey = Object.fromEntries(toolSettingFields(schema).map((f) => [f.key, f]))
    expect(byKey.rate_limit).toMatchObject({
      kind: 'integer',
      minimum: 1,
      maximum: 5000,
      defaultValue: 150,
      common: 'rate',
      flag: '-rate-limit',
      scope: 'scan',
    })
    expect(byKey.scan_strategy).toMatchObject({
      kind: 'enum',
      values: ['auto', 'host-spray'],
      group: 'Engine',
    })
    expect(byKey.headless).toMatchObject({ kind: 'boolean', tier: 'T2' })
    expect(byKey.headless.flag).toBeUndefined()
    expect(byKey.severity).toMatchObject({ kind: 'multi', values: ['low', 'high'] })
    expect(byKey['dns.resolvers']).toMatchObject({ kind: 'list', group: 'DNS' })
  })

  it('returns nothing for something that is not a schema', () => {
    expect(toolSettingFields(null)).toEqual([])
    expect(toolSettingFields({ properties: 'x' })).toEqual([])
  })
})

describe('draft and values', () => {
  const fields = toolSettingFields(schema)

  it('round-trips stored values, numbers parsed and group keys nested', () => {
    const stored = { rate_limit: 300, severity: ['high'], dns: { resolvers: ['192.0.2.1'] } }
    const draft = draftFromValues(fields, stored)
    expect(draft.rate_limit).toBe('300')
    expect(valuesFromDraft(fields, draft)).toEqual(stored)
  })

  it('leaves unset fields out so they keep their default', () => {
    expect(valuesFromDraft(fields, { rate_limit: undefined, scan_strategy: '' })).toEqual({})
  })

  it('sends a number that does not parse as typed, so the API names the field', () => {
    expect(valuesFromDraft(fields, { rate_limit: 'fast' })).toEqual({ rate_limit: 'fast' })
  })

  it('maps an error path to a field key', () => {
    expect(problemKey('/dns/resolvers')).toBe('dns.resolvers')
    expect(problemKey('/rate_limit')).toBe('rate_limit')
    expect(problemKey('')).toBe('')
  })
})

describe('changes from defaults', () => {
  const int: ToolSettingField = {
    key: 'rate_limit',
    kind: 'integer',
    flag: '-rate-limit',
    defaultValue: 150,
    scope: 'sensor',
    tier: 'T0',
    order: 0,
  }
  const list: ToolSettingField = {
    key: 'severity',
    kind: 'multi',
    defaultValue: ['high', 'critical'],
    scope: 'sensor',
    tier: 'T0',
    order: 0,
  }

  it('treats unset and default-equal values as unchanged', () => {
    expect(isChangedValue(int, undefined)).toBe(false)
    expect(isChangedValue(int, '')).toBe(false)
    expect(isChangedValue(int, '150')).toBe(false)
    expect(isChangedValue(int, '300')).toBe(true)
    expect(isChangedValue(int, 'abc')).toBe(true)
    expect(isChangedValue(list, ['high', 'critical'])).toBe(false)
    expect(isChangedValue(list, ['high'])).toBe(true)
    expect(isChangedValue(list, [])).toBe(false)
  })

  it('summarises at most three changes by native flag, then an ellipsis', () => {
    const fields = ['a', 'b', 'c', 'd'].map((k) => ({ ...int, key: k, flag: undefined }))
    const draft = { a: '1', b: '2', c: '3', d: '4' }
    const changed = changedFields(fields, draft)
    expect(changed).toHaveLength(4)
    expect(changeSummaryList(changed, draft)).toBe('a 1, b 2, c 3, …')
    expect(changeSummaryList([int], { rate_limit: '300' })).toBe('rate-limit 300')
  })

  it('matches a search by key, flag or label', () => {
    expect(fieldMatches(int, 'Rate limit', 'rate-l')).toBe(true)
    expect(fieldMatches(int, 'Rate limit', 'rate l')).toBe(true)
    expect(fieldMatches(int, 'Rate limit', 'timeout')).toBe(false)
    expect(fieldMatches(int, 'Rate limit', '')).toBe(false)
  })
})
