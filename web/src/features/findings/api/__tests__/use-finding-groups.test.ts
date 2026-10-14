/**
 * Finding Groups URL builder tests
 *
 * Covers buildGroupsUrl query-param assembly, in particular the
 * `assigned_to_me` filter behind the "Show only mine" checkbox.
 */

import { describe, it, expect } from 'vitest'
import { buildGroupsUrl } from '../use-finding-groups'

describe('buildGroupsUrl', () => {
  it('always includes the group_by dimension', () => {
    const url = buildGroupsUrl({ group_by: 'cve_id' })
    expect(url.startsWith('/api/v1/findings/groups?')).toBe(true)
    expect(new URLSearchParams(url.split('?')[1]).get('group_by')).toBe('cve_id')
  })

  it('sends related_to=me when assigned_to_me is set (RFC-048 name)', () => {
    const url = buildGroupsUrl({ group_by: 'cve_id', assigned_to_me: true })
    const params = new URLSearchParams(url.split('?')[1])
    expect(params.get('related_to')).toBe('me')
  })

  it('omits assigned_to_me when the field is false or unset', () => {
    const falseUrl = buildGroupsUrl({ group_by: 'cve_id', assigned_to_me: false })
    expect(new URLSearchParams(falseUrl.split('?')[1]).has('related_to')).toBe(false)

    const unsetUrl = buildGroupsUrl({ group_by: 'cve_id' })
    expect(new URLSearchParams(unsetUrl.split('?')[1]).has('related_to')).toBe(false)
  })

  it('preserves other filters alongside assigned_to_me', () => {
    const url = buildGroupsUrl({
      group_by: 'owner_id',
      statuses: 'new,confirmed',
      assigned_to_me: true,
    })
    const params = new URLSearchParams(url.split('?')[1])
    expect(params.get('group_by')).toBe('owner_id')
    expect(params.get('status')).toBe('new,confirmed')
    expect(params.get('related_to')).toBe('me')
  })

  it('runs the list filter when given one, with its own paging and no sort', () => {
    const url = buildGroupsUrl({
      group_by: 'rule_id',
      page: 2,
      per_page: 25,
      query: {
        search: 'injection',
        priority_classes: ['P0', 'P1'],
        is_in_kev: true,
        sla_statuses: ['overdue'],
        asset_id: 'a1',
        state: 'open',
        exclude_statuses: ['draft'],
        page: 7,
        per_page: 100,
        sort: '-severity',
      },
      // The facet fields are ignored when a query is given.
      severities: 'low',
    })
    const params = new URLSearchParams(url.split('?')[1])
    expect(url.startsWith('/api/v1/findings/groups?')).toBe(true)
    expect(params.get('group_by')).toBe('rule_id')
    expect(params.get('q')).toBe('injection')
    expect(params.get('priority_class')).toBe('P0,P1')
    expect(params.get('is_in_kev')).toBe('true')
    expect(params.get('sla_status')).toBe('overdue')
    expect(params.get('asset_id')).toBe('a1')
    expect(params.get('state')).toBe('open')
    expect(params.get('status_not')).toBe('draft')
    expect(params.get('page')).toBe('2')
    expect(params.get('per_page')).toBe('25')
    expect(params.has('sort')).toBe(false)
    expect(params.has('severity')).toBe(false)
  })
})
