import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { PAGE_PARAMS } from '../../lib/drilldown'
import { CONTEXT_FILTER_PARAMS, OWNED_FILTER_PARAMS } from '../contract'
import { NON_FILTER_PARAMS, readFilters, type FilterContract } from '../model'

/**
 * A URL parameter the findings page writes for itself must be either a filter
 * or a known non-filter: otherwise the filter bar shows it as an
 * "Unknown filter" chip and counts it as an active filter.
 */

const contract: FilterContract = {
  fields: [{ name: 'rule_id', type: 'string', ops: ['in', 'not_in'] }],
}

// Params the page and its helpers write that are not filters.
const WRITTEN_NON_FILTERS = [
  ...PAGE_PARAMS, // group, page, from (drilldown.ts)
  'from', // from=group:<dimension> and from=task:<id>
  'per_page',
  'sort',
  'q',
  'view',
  'density',
  'columns',
  'tab',
  'state',
  'strict',
  'fq',
]

describe('params the findings page writes', () => {
  it.each([...new Set(WRITTEN_NON_FILTERS)])('%s is a non-filter param', (param) => {
    expect(NON_FILTER_PARAMS.has(param)).toBe(true)
    const { filters, unknown } = readFilters(new URLSearchParams({ [param]: 'x' }), contract)
    expect(filters).toEqual([])
    expect(unknown).toEqual([])
  })

  it('every literal param the page and the drill-down helper set is registered', () => {
    const root = join(__dirname, '..', '..', '..', '..')
    const files = [
      join(root, 'app', '(dashboard)', 'findings', 'page.tsx'),
      join(root, 'features', 'findings', 'lib', 'drilldown.ts'),
      join(root, 'features', 'findings', 'components', 'finding-detail-drawer.tsx'),
    ]
    const known = new Set<string>([
      ...NON_FILTER_PARAMS,
      ...OWNED_FILTER_PARAMS,
      ...CONTEXT_FILTER_PARAMS,
    ])
    const written = new Set<string>()
    for (const f of files) {
      const src = readFileSync(f, 'utf8')
      for (const m of src.matchAll(/(?:\.set|useUrlFilter|useUrlFilterList)\(\s*'([a-z_]+)'/g)) {
        written.add(m[1])
      }
    }
    expect(written.size).toBeGreaterThan(5)
    // Every written literal is a filter the page owns or draws, or a non-filter.
    expect([...written].filter((p) => !known.has(p))).toEqual([])
  })

  it('a drill-down URL yields one filter, no unknown param', () => {
    const { filters, unknown } = readFilters(
      new URLSearchParams('rule_id=github-pat&from=group:rule_id'),
      contract
    )
    expect(filters.map((f) => f.param)).toEqual(['rule_id'])
    expect(unknown).toEqual([])
  })
})
