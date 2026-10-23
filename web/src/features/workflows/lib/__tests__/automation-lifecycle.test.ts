import { describe, expect, it } from 'vitest'

import type { WorkflowCatalog } from '@/lib/api/workflow-types'
import {
  approvalState,
  catalogEntriesFor,
  countsFromNodeRuns,
  countsFromSteps,
  problemsFromError,
  publishRequirements,
  removedTypeOf,
  skippedEntries,
} from '../automation-lifecycle'

const catalog: WorkflowCatalog = {
  triggers: [{ type: 'finding_created', allowed: true }],
  actions: [
    { type: 'add_tags', permission: 'findings:write', allowed: true, risk_class: 'low' },
    { type: 'trigger_scan', permission: 'scans:execute', allowed: false, risk_class: 'high' },
  ],
  notifications: [{ type: 'slack', permission: 'integrations:read', allowed: true }],
}

describe('catalog helpers', () => {
  it('returns the catalog list of a step kind and nothing for a condition', () => {
    expect(catalogEntriesFor(catalog, 'action').map((e) => e.type)).toEqual([
      'add_tags',
      'trigger_scan',
    ])
    expect(catalogEntriesFor(catalog, 'condition')).toEqual([])
    expect(catalogEntriesFor(undefined, 'action')).toEqual([])
  })

  it('flags a stored type the catalog does not list, by id', () => {
    expect(removedTypeOf(catalog, 'action', { action_type: 'http_request' })).toBe('http_request')
    expect(removedTypeOf(catalog, 'trigger', { trigger_type: 'schedule' })).toBe('schedule')
    expect(removedTypeOf(catalog, 'notification', { notification_type: 'pagerduty' })).toBe(
      'pagerduty'
    )
    // A disallowed type is still a runnable type: not removed.
    expect(removedTypeOf(catalog, 'action', { action_type: 'trigger_scan' })).toBeUndefined()
    expect(removedTypeOf(catalog, 'condition', { condition_expr: 'x' })).toBeUndefined()
  })

  it('flags nothing before the catalog has loaded', () => {
    expect(removedTypeOf(undefined, 'action', { action_type: 'http_request' })).toBeUndefined()
  })
})

describe('publish gate', () => {
  it('needs nothing extra for low, step-up for elevated, step-up and a second approver for high', () => {
    expect(publishRequirements('low')).toEqual({ stepUp: false, secondApprover: false })
    expect(publishRequirements('elevated')).toEqual({ stepUp: true, secondApprover: false })
    expect(publishRequirements('high')).toEqual({ stepUp: true, secondApprover: true })
    expect(publishRequirements(undefined)).toEqual({ stepUp: false, secondApprover: false })
  })

  const pending = {
    pending_version: {
      id: 'v4',
      version: 4,
      digest: 'sha256:abc',
      risk_class: 'high' as const,
      published_by: 'u-alice',
      created_at: '2026-10-20T00:00:00Z',
    },
  }

  it('lets another publisher approve, never the publisher', () => {
    expect(approvalState(pending, 'u-bob', true)).toBe('can_approve')
    expect(approvalState(pending, 'u-alice', true)).toBe('self')
    expect(approvalState(pending, 'u-bob', false)).toBe('no_permission')
    expect(approvalState({ pending_version: null }, 'u-bob', true)).toBe('none')
  })
})

describe('counts', () => {
  it('keys preview steps and node runs by node key', () => {
    const m = countsFromSteps([
      { node_key: 'c1', in: 61, out: 14, skipped: { condition_false: 47 } },
    ])
    expect(m.get('c1')).toEqual({ in: 61, out: 14, skipped: { condition_false: 47 } })
    const r = countsFromNodeRuns([
      {
        id: 'nr1',
        workflow_run_id: 'r1',
        node_id: 'n1',
        node_key: 'a1',
        node_type: 'action',
        status: 'completed',
        in_count: 12,
        out_count: 11,
        skipped: { 'refused:already_in_active_task': 1 },
      },
    ])
    expect(r.get('a1')).toEqual({
      in: 12,
      out: 11,
      skipped: { 'refused:already_in_active_task': 1 },
    })
  })

  it('orders skipped reasons largest first and drops zeros', () => {
    expect(skippedEntries({ a: 1, b: 5, c: 0 })).toEqual([
      ['b', 5],
      ['a', 1],
    ])
  })
})

describe('problemsFromError', () => {
  it('reads the problems of a refused publish', () => {
    const err = {
      code: 'WORKFLOW_INVALID',
      statusCode: 400,
      details: { problems: [{ code: 'GRAPH_CYCLE', message: 'cycle', node_key: 'a' }, 'junk'] },
    }
    expect(problemsFromError(err)).toEqual([
      { code: 'GRAPH_CYCLE', message: 'cycle', node_key: 'a' },
    ])
    expect(problemsFromError({ code: 'FORBIDDEN' })).toBeNull()
  })
})
