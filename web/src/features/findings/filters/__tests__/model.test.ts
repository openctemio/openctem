import { describe, expect, it } from 'vitest'
import {
  editableOps,
  groupOf,
  humanize,
  paramFor,
  paramMeaning,
  pickableFields,
  readFilters,
  valuesOf,
  viewFields,
  viewFilters,
  withFilter,
  withoutParam,
  type FieldContract,
  type FilterContract,
} from '../model'
import { OWNED_FIELDS, withOwnedFields } from '../contract'

const contract: FilterContract = {
  fields: [
    { name: 'severity', type: 'enum', ops: ['in', 'not_in'], enum: ['critical', 'high', 'low'] },
    { name: 'epss_score', type: 'number', ops: ['gte', 'gt', 'lte', 'lt'] },
    { name: 'first_detected_at', type: 'date-time', ops: ['gte', 'gt', 'lte', 'lt'] },
    { name: 'is_in_kev', type: 'boolean', ops: ['eq'] },
    { name: 'file_path', type: 'string', ops: ['contains'] },
    { name: 'assigned_to', type: 'id', ops: ['in', 'not_in', 'is_null'], nullable: true },
    { name: 'asset_criticality', type: 'enum', ops: ['in', 'not_in'], enum: ['critical', 'low'] },
    { name: 'asset_tag', type: 'string', ops: ['in', 'not_in'] },
    { name: 'id', type: 'id', ops: ['in', 'not_in'] },
    { name: 'brand_new_field', type: 'string', ops: ['in'] },
    { name: 'network_port', type: 'integer', ops: ['in', 'not_in', 'gte', 'lte'] },
    { name: 'status', type: 'enum', ops: ['in', 'ne', 'not_in'] },
  ],
}
const field = (n: string) => contract.fields.find((f) => f.name === n) as FieldContract

describe('paramFor / paramMeaning', () => {
  const cases: Array<[string, string, string]> = [
    ['severity', 'in', 'severity'],
    ['severity', 'not_in', 'severity_not'],
    ['epss_score', 'gte', 'epss_score_gte'],
    ['epss_score', 'gt', 'epss_score_gt'],
    ['epss_score', 'lte', 'epss_score_lte'],
    ['epss_score', 'lt', 'epss_score_lt'],
    ['is_in_kev', 'eq', 'is_in_kev'],
    ['file_path', 'contains', 'file_path'],
    ['assigned_to', 'is_null', 'assigned_to_null'],
    ['network_port', 'gte', 'network_port_gte'],
  ]
  for (const [f, op, param] of cases) {
    it(`${f} ${op} <-> ${param}`, () => {
      expect(paramFor(field(f), op as never)).toBe(param)
      const m = paramMeaning(param, contract)
      expect(m?.field.name).toBe(f)
      expect(m?.op).toBe(op)
    })
  }

  it('a bare param on a field that has no in/eq/contains is no filter', () => {
    expect(paramMeaning('epss_score', contract)).toBeUndefined()
  })

  it('an unknown param means nothing; an operator the field lacks too', () => {
    expect(paramMeaning('sevrity', contract)).toBeUndefined()
    expect(paramMeaning('is_in_kev_gte', contract)).toBeUndefined()
    expect(paramFor(field('is_in_kev'), 'gte')).toBeUndefined()
  })

  it('"ne" reads as the _not param', () => {
    expect(paramMeaning('status_not', contract)?.op).toBe('not_in')
  })
})

describe('valuesOf', () => {
  it('splits lists, keeps single values whole', () => {
    expect(valuesOf('in', 'a, b ,,c')).toEqual(['a', 'b', 'c'])
    expect(valuesOf('gte', '0.5')).toEqual(['0.5'])
    expect(valuesOf('contains', 'a,b')).toEqual(['a,b'])
    expect(valuesOf('in', '')).toEqual([])
  })
})

describe('readFilters', () => {
  it('reads one chip per filter param, in URL order, with its operator', () => {
    const q = new URLSearchParams(
      'severity=critical,high&epss_score_gte=0.5&is_in_kev=true&severity_not=low&page=2&sort=-created_at&q=x'
    )
    const { filters, unknown } = readFilters(q, contract)
    expect(unknown).toEqual([])
    expect(filters.map((f) => [f.param, f.field, f.op, f.values])).toEqual([
      ['severity', 'severity', 'in', ['critical', 'high']],
      ['epss_score_gte', 'epss_score', 'gte', ['0.5']],
      ['is_in_kev', 'is_in_kev', 'eq', ['true']],
      ['severity_not', 'severity', 'not_in', ['low']],
    ])
  })

  it('never turns page params into chips', () => {
    const q = new URLSearchParams(
      'page=2&per_page=50&sort=-created_at&q=x&group=cve_id&view=verify&density=compact&columns=severity,status&tab=x&state=open'
    )
    expect(readFilters(q, contract)).toEqual({ filters: [], unknown: [] })
  })

  it('reports an unknown param instead of dropping it', () => {
    const { filters, unknown } = readFilters(
      new URLSearchParams('sevrity=high&severity=low'),
      contract
    )
    expect(unknown).toEqual(['sevrity'])
    expect(filters).toHaveLength(1)
  })

  it('skips params something else draws', () => {
    const q = new URLSearchParams('asset_id=a&severity=low')
    const { filters, unknown } = readFilters(q, contract, new Set(['asset_id']))
    expect(unknown).toEqual([])
    expect(filters.map((f) => f.param)).toEqual(['severity'])
  })

  it('a field the web has never heard of is still a chip', () => {
    const { filters } = readFilters(new URLSearchParams('brand_new_field=x'), contract)
    expect(filters[0]).toMatchObject({ field: 'brand_new_field', op: 'in', values: ['x'] })
  })

  it('an empty value is no filter', () => {
    expect(readFilters(new URLSearchParams('severity='), contract).filters).toEqual([])
  })
})

describe('viewFilters', () => {
  const doc = (...all: unknown[]) => ({ v: 1, filter: { all } })

  it('turns the top-level conditions of a stored view into locked chips', () => {
    const r = viewFilters(
      doc(
        { field: 'severity', op: 'in', value: ['critical', 'high'] },
        { field: 'epss_score', op: 'gte', value: 0.1 },
        { field: 'is_in_kev', op: 'eq', value: true },
        { field: 'severity', op: 'not_in', value: ['low'] }
      ),
      contract
    )
    expect(r.complex).toBe(false)
    expect(r.filters.every((f) => f.locked)).toBe(true)
    expect(r.filters.map((f) => [f.param, f.values])).toEqual([
      ['severity', ['critical', 'high']],
      ['epss_score_gte', ['0.1']],
      ['is_in_kev', ['true']],
      ['severity_not', ['low']],
    ])
  })

  it('a single leaf is a view of one condition', () => {
    const r = viewFilters(
      { v: 1, filter: { field: 'severity', op: 'in', value: ['low'] } },
      contract
    )
    expect(r.filters.map((f) => f.param)).toEqual(['severity'])
  })

  it('an any or a not below the top is reported, not guessed at', () => {
    const r = viewFilters(
      doc(
        { field: 'severity', op: 'in', value: ['low'] },
        { any: [{ field: 'is_in_kev', op: 'eq', value: true }] }
      ),
      contract
    )
    expect(r.complex).toBe(true)
    expect(r.filters.map((f) => f.param)).toEqual(['severity'])
    expect(viewFilters({ v: 1, filter: { any: [] } }, contract)).toEqual({
      filters: [],
      complex: true,
    })
  })

  it('a condition on a field or operator the contract lacks is reported as complex', () => {
    expect(viewFilters(doc({ field: 'nope', op: 'in', value: ['x'] }), contract).complex).toBe(true)
    expect(viewFilters(doc({ field: 'is_in_kev', op: 'gte', value: 1 }), contract).complex).toBe(
      true
    )
  })

  it('nothing for a view without a filter', () => {
    expect(viewFilters(undefined, contract)).toEqual({ filters: [], complex: false })
    expect(viewFilters({ v: 1, sort: ['-created_at'] }, contract)).toEqual({
      filters: [],
      complex: false,
    })
  })

  it('ignores values that are objects', () => {
    const r = viewFilters(doc({ field: 'severity', op: 'in', value: [{ bad: 1 }] }), contract)
    expect(r.filters).toEqual([])
  })
})

describe('viewFields', () => {
  it('names the fields a view already sets', () => {
    const f = viewFields({
      v: 1,
      filter: { all: [{ field: 'severity', op: 'in', value: ['low'] }, { any: [] }] },
    })
    expect([...f]).toEqual(['severity'])
    expect(viewFields(undefined).size).toBe(0)
  })
})

describe('withFilter / withoutParam', () => {
  it('sets a list filter and resets the page', () => {
    const next = withFilter(new URLSearchParams('page=3&q=x'), field('severity'), 'in', [
      'critical',
      'high',
    ])
    expect(next.get('severity')).toBe('critical,high')
    expect(next.has('page')).toBe(false)
    expect(next.get('q')).toBe('x')
  })

  it('replaces the same param, keeps other operators of the same field', () => {
    const next = withFilter(
      new URLSearchParams('severity=low&severity_not=high'),
      field('severity'),
      'in',
      ['critical']
    )
    expect(next.get('severity')).toBe('critical')
    expect(next.get('severity_not')).toBe('high')
  })

  it('a single-value operator keeps the first value only', () => {
    const next = withFilter(new URLSearchParams(), field('epss_score'), 'gte', ['0.5', '0.9'])
    expect(next.get('epss_score_gte')).toBe('0.5')
  })

  it('no values removes the filter', () => {
    const next = withFilter(new URLSearchParams('severity=low'), field('severity'), 'in', [' '])
    expect(next.has('severity')).toBe(false)
  })

  it('does nothing for an operator the field cannot have', () => {
    expect(
      withFilter(new URLSearchParams('a=1'), field('is_in_kev'), 'gte', ['1']).toString()
    ).toBe('a=1')
  })

  it('withoutParam removes one param and the page', () => {
    const next = withoutParam(new URLSearchParams('severity=low&q=x&page=2'), 'severity')
    expect(next.toString()).toBe('q=x')
  })
})

describe('editableOps', () => {
  it('lists operators in reading order and folds "ne" into "not_in"', () => {
    expect(editableOps(field('status'))).toEqual(['in', 'not_in'])
    expect(editableOps(field('epss_score'))).toEqual(['gte', 'gt', 'lte', 'lt'])
    expect(editableOps(field('assigned_to'))).toEqual(['in', 'not_in', 'is_null'])
  })
})

describe('pickableFields', () => {
  it('groups by entity in order and leaves plumbing fields out', () => {
    const groups = pickableFields(contract, { canReadAssets: true })
    expect(groups.map((g) => g.group)).toEqual([
      'exploitation',
      'finding',
      'asset',
      'work',
      'other',
    ])
    const all = groups.flatMap((g) => g.fields.map((f) => f.name))
    expect(all).not.toContain('id')
    expect(all).toContain('brand_new_field')
    expect(groups.find((g) => g.group === 'other')?.fields.map((f) => f.name)).toEqual([
      'brand_new_field',
    ])
  })

  it('offers no asset-derived field without permission to read assets', () => {
    const all = pickableFields(contract, { canReadAssets: false }).flatMap((g) =>
      g.fields.map((f) => f.name)
    )
    expect(all).not.toContain('asset_criticality')
    expect(all).not.toContain('asset_tag')
    expect(all).toContain('severity')
  })

  it('groupOf places known fields and leaves unknown ones in other', () => {
    expect(groupOf('epss_score')).toBe('exploitation')
    expect(groupOf('severity')).toBe('finding')
    expect(groupOf('asset_tag')).toBe('asset')
    expect(groupOf('assigned_to')).toBe('work')
    expect(groupOf('zzz')).toBe('other')
  })
})

describe('owned fields', () => {
  it('read their chips without the contract', () => {
    const c = withOwnedFields(undefined)
    const { filters, unknown } = readFilters(
      new URLSearchParams(
        'severity=high&severity_not=low&is_in_kev=true&pending_approval=true&acceptance_expires_at_lte=P30D&sla_status=overdue,exceeded&related_to=me'
      ),
      c
    )
    expect(unknown).toEqual([])
    expect(filters.map((f) => f.param)).toEqual([
      'severity',
      'severity_not',
      'is_in_kev',
      'pending_approval',
      'acceptance_expires_at_lte',
      'sla_status',
      'related_to',
    ])
  })

  it('the loaded contract wins for a field it has', () => {
    const c = withOwnedFields({
      fields: [{ name: 'severity', type: 'enum', ops: ['in'], enum: ['x'] }],
    })
    expect(c.fields.filter((f) => f.name === 'severity')).toHaveLength(1)
    expect(c.fields.find((f) => f.name === 'severity')?.enum).toEqual(['x'])
    expect(c.fields.length).toBe(OWNED_FIELDS.length)
  })
})

describe('humanize', () => {
  it('makes a label out of a field name', () => {
    expect(humanize('first_detected_at')).toBe('First detected at')
  })
})
