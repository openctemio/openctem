import { describe, it, expect } from 'vitest'
import { parseFindingLens, FINDING_LENSES, DEFAULT_FINDING_LENS } from '../state-lens'
import { buildGroupsUrl } from '../../api/use-finding-groups'
import { buildFindingsQuery } from '../../api/use-findings-api'

describe('findings state lens', () => {
  it('has the four lenses of decision C2, Open first and default', () => {
    expect(FINDING_LENSES.map((l) => l.value)).toEqual(['open', 'fixed', 'dispositioned', 'all'])
    expect(DEFAULT_FINDING_LENS).toBe('open')
  })

  it('parses only known lenses', () => {
    expect(parseFindingLens('fixed')).toBe('fixed')
    expect(parseFindingLens('closed')).toBe('open')
    expect(parseFindingLens(null)).toBe('open')
  })

  it('sends the lens to the list, stats, export and groups requests alike', () => {
    expect(buildFindingsQuery({ state: 'dispositioned' }).get('state')).toBe('dispositioned')
    expect(
      new URL(buildGroupsUrl({ group_by: 'cve_id', state: 'fixed' }), 'http://x').searchParams.get(
        'state'
      )
    ).toBe('fixed')
  })
})
