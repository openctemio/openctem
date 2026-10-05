import { describe, it, expect } from 'vitest'
import {
  buildDrillDownSearch,
  buildGroupedSearch,
  drillOrigin,
  drillValue,
  removeFilterParam,
  DRILL_PARAM,
} from '../drilldown'
import { GROUP_BY_DIMENSIONS } from '../../components/finding-groups-table'

const q = (s: string) => new URLSearchParams(s)

describe('findings drill-down URLs', () => {
  it('keeps every other filter, drops the grouping and the page, records the origin', () => {
    const next = buildDrillDownSearch(
      q('severity=critical&q=log4j&group=rule_id&page=3'),
      'rule_id',
      '10114'
    )
    expect(next.get('severity')).toBe('critical')
    expect(next.get('q')).toBe('log4j')
    expect(next.get('rule_id')).toBe('10114')
    expect(next.get('from')).toBe('group:rule_id')
    expect(next.has('group')).toBe(false)
    expect(next.has('page')).toBe(false)
  })

  it('maps every group dimension to a list filter (View on all nine)', () => {
    expect(Object.keys(DRILL_PARAM).sort()).toEqual([...GROUP_BY_DIMENSIONS].sort())
    for (const dim of GROUP_BY_DIMENSIONS) {
      const next = buildDrillDownSearch(q(`group=${dim}`), dim, 'k')
      expect(next.get(DRILL_PARAM[dim])).toBe('k')
      expect(drillOrigin(next, GROUP_BY_DIMENSIONS)).toBe(dim)
    }
    expect(DRILL_PARAM.owner_id).toBe('asset_owner_id')
  })

  it('drills the Unassigned owner group to asset_owner_id_null', () => {
    const next = buildDrillDownSearch(q('group=owner_id'), 'owner_id', 'unassigned')
    expect(next.get('asset_owner_id_null')).toBe('true')
    expect(next.has('asset_owner_id')).toBe(false)
    expect(drillOrigin(next, GROUP_BY_DIMENSIONS)).toBe('owner_id')
    expect(drillValue(next, 'owner_id')).toBe('Unassigned')
  })

  it('narrows a multi-value facet to the one group value', () => {
    const next = buildDrillDownSearch(
      q('severity=critical,high&group=severity'),
      'severity',
      'high'
    )
    expect(next.get('severity')).toBe('high')
  })

  it('builds the way back to the grouped view with the same filters', () => {
    const drilled = buildDrillDownSearch(q('severity=critical&group=rule_id'), 'rule_id', '10114')
    const back = buildGroupedSearch(drilled, 'rule_id')
    expect(back.toString()).toBe(q('severity=critical&group=rule_id').toString())
  })

  it('removes only the chip param, and ends the drill-down with the drilled one', () => {
    const drilled = buildDrillDownSearch(q('severity=critical&group=rule_id'), 'rule_id', '10114')
    const noRule = removeFilterParam(drilled, 'rule_id')
    expect(noRule.get('severity')).toBe('critical')
    expect(noRule.has('rule_id')).toBe(false)
    expect(noRule.has('from')).toBe(false)
    expect(drillOrigin(noRule, GROUP_BY_DIMENSIONS)).toBeNull()

    const noSeverity = removeFilterParam(drilled, 'severity')
    expect(noSeverity.get('rule_id')).toBe('10114')
    expect(noSeverity.get('from')).toBe('group:rule_id')
  })

  it('ignores a forged or stale origin', () => {
    expect(drillOrigin(q('from=group:evil&rule_id=1'), GROUP_BY_DIMENSIONS)).toBeNull()
    expect(drillOrigin(q('from=elsewhere&rule_id=1'), GROUP_BY_DIMENSIONS)).toBeNull()
    // The drilled filter was removed by hand: no breadcrumb.
    expect(drillOrigin(q('from=group:rule_id'), GROUP_BY_DIMENSIONS)).toBeNull()
  })
})
