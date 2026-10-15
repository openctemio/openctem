import { describe, expect, it } from 'vitest'
import {
  allowedDirections,
  defaultTransform,
  layoutWorkflow,
  normalizeSpec,
  rowFor,
  shapeOf,
  unmappedRequired,
  workflowEdges,
} from '../lib/mapping-utils'
import { renderSample } from '../lib/template-sample'
import type { CatalogAttribute, FieldMeta, MappingSpec } from '../types/ticket-mapping.types'

const sev: CatalogAttribute = {
  path: 'finding.severity',
  kind: 'finding',
  type: 'enum',
  tier: 'title_only',
  inbound: 'never',
  enum: ['high'],
}
const assignee: CatalogAttribute = {
  path: 'finding.assignee',
  kind: 'finding',
  type: 'user',
  tier: 'summary',
  inbound: 'assign',
}
const cves: CatalogAttribute = {
  path: 'finding.cve_ids',
  kind: 'finding',
  type: 'list',
  tier: 'summary',
  inbound: 'never',
}
const title: CatalogAttribute = {
  path: 'finding.title',
  kind: 'finding',
  type: 'text',
  tier: 'title_only',
  inbound: 'never',
}

const priority: FieldMeta = {
  id: 'priority',
  name: 'Priority',
  required: false,
  has_default: true,
  schema: { type: 'priority' },
}
const team: FieldMeta = {
  id: 'customfield_1',
  name: 'Team',
  required: true,
  has_default: false,
  schema: { type: 'option' },
}
const labels: FieldMeta = {
  id: 'labels',
  name: 'Labels',
  required: false,
  has_default: false,
  schema: { type: 'array', items: 'string' },
}
const userField: FieldMeta = {
  id: 'assignee',
  name: 'Assignee',
  required: false,
  has_default: false,
  schema: { type: 'user' },
}
const text: FieldMeta = {
  id: 'customfield_2',
  name: 'CVE',
  required: false,
  has_default: false,
  schema: { type: 'string' },
}

describe('mapping-utils', () => {
  it('classifies field shapes like the API', () => {
    expect(shapeOf(priority.schema)).toBe('option')
    expect(shapeOf(labels.schema)).toBe('labels')
    expect(shapeOf({ type: 'array', items: 'option' })).toBe('options')
    expect(shapeOf({ type: 'datetime' })).toBe('date')
    expect(shapeOf({ type: 'team' })).toBe('other')
  })

  it('locks attributes that can never flow in, and templates', () => {
    expect(allowedDirections(rowFor(sev, priority), sev)).toEqual(['out'])
    expect(allowedDirections(rowFor(assignee, userField), assignee)).toEqual(['out', 'in', 'both'])
    const tpl = {
      ...rowFor(title, text),
      source: { kind: 'template' as const, template: '{{ finding.title }}' },
    }
    expect(allowedDirections(tpl, assignee)).toEqual(['out'])
  })

  it('picks a default transform for the field shape', () => {
    expect(defaultTransform(sev, priority)).toBe('value_map')
    expect(defaultTransform(assignee, userField)).toBe('user')
    expect(defaultTransform(cves, labels)).toBe('list')
    expect(defaultTransform(cves, text)).toBe('join')
  })

  it('reports required fields without an outbound row', () => {
    const spec: MappingSpec = normalizeSpec({
      minimization: 'summary',
      fields: [rowFor(sev, priority)],
      status: {},
      comments_in: false,
      comments_out: true,
    })
    expect(unmappedRequired(spec, [priority, team]).map((f) => f.id)).toEqual(['customfield_1'])
    const inbound = { ...rowFor(sev, team), direction: 'in' as const }
    expect(unmappedRequired({ ...spec, fields: [inbound] }, [team]).map((f) => f.id)).toEqual([
      'customfield_1',
    ])
  })

  it('lays the workflow out by category and splits global transitions', () => {
    const wf = {
      statuses: [
        { id: '1', name: 'To Do', category: 'new' },
        { id: '3', name: 'In Progress', category: 'indeterminate' },
        { id: '10', name: 'Done', category: 'done' },
        { id: '4', name: 'Review', category: 'indeterminate' },
      ],
      transitions: [
        { id: '11', name: 'Start', from: ['1'], to: '3' },
        { id: '99', name: 'Close', to: '10' },
      ],
    }
    const nodes = layoutWorkflow(wf, 100, 10)
    expect(nodes.find((n) => n.status.id === '1')).toMatchObject({ x: 0, y: 0 })
    expect(nodes.find((n) => n.status.id === '4')).toMatchObject({ x: 100, y: 10 })
    expect(nodes.find((n) => n.status.id === '10')).toMatchObject({ x: 200 })
    const { edges, global } = workflowEdges(wf)
    expect(edges).toEqual([{ from: '1', to: '3', name: 'Start' }])
    expect(global).toEqual([{ to: '10', name: 'Close' }])
  })
})

describe('template sample render', () => {
  const attrs = [sev, cves, title]
  const filters = ['join', 'truncate', 'date', 'default', 'upper', 'lower', 'first', 'count']
  it('renders paths with filters', () => {
    const r = renderSample(
      '[{{ finding.severity | upper }}] {{ finding.title | truncate:5 }} {{ finding.cve_ids | count }}',
      attrs,
      filters
    )
    expect(r.errors).toEqual([])
    expect(r.text).toBe('[HIGH] SQL … 1')
  })
  it('reports unknown paths and filters', () => {
    const r = renderSample('{{ finding.secret }} {{ finding.title | exec }}', attrs, filters)
    expect(r.errors).toEqual(['finding.secret', 'exec'])
  })
})
