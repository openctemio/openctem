import { describe, expect, it } from 'vitest'

import { WORKFLOW_ACTION_TYPES, WORKFLOW_TRIGGER_TYPES } from '@/lib/api/workflow-types'
import type { WorkflowEdge, WorkflowNode } from '@/lib/api/workflow-types'
import {
  automationConnectionRule,
  fromApiGraph,
  nextNodeKey,
  starterGraph,
  toApiGraph,
  unreachableNodes,
} from '../automation-graph'

const n = (id: string, type: string) => ({ id, type })

describe('starter graph', () => {
  it('is one manual trigger, never a demo graph', () => {
    const g = starterGraph()
    expect(g.nodes).toHaveLength(1)
    expect(g.nodes[0].type).toBe('trigger')
    expect(g.nodes[0].data.config).toEqual({ trigger_type: 'manual' })
    expect(g.edges).toEqual([])
  })

  it('is what an empty stored workflow opens as', () => {
    expect(fromApiGraph([], [])).toEqual(starterGraph())
    expect(fromApiGraph(undefined, undefined)).toEqual(starterGraph())
  })
})

describe('automationConnectionRule', () => {
  const nodes = [n('t', 'trigger'), n('c', 'condition'), n('a', 'action'), n('b', 'action')]
  const edges = [
    { source: 't', target: 'c' },
    { source: 'c', target: 'a' },
    { source: 'a', target: 'b' },
  ]
  const rule = automationConnectionRule(nodes, edges)

  it('refuses an edge into a trigger', () => {
    const v = rule('b', 't')
    expect(v.ok).toBe(false)
  })

  it('refuses a loop and a self edge', () => {
    expect(rule('b', 'c').ok).toBe(false)
    expect(rule('a', 'a').ok).toBe(false)
  })

  it('accepts a forward edge', () => {
    expect(rule('t', 'b').ok).toBe(true)
  })
})

describe('unreachableNodes', () => {
  it('lists the nodes no trigger leads to', () => {
    const nodes = [n('t', 'trigger'), n('a', 'action'), n('x', 'action'), n('y', 'notification')]
    expect(
      unreachableNodes(nodes, [
        { source: 't', target: 'a' },
        { source: 'x', target: 'y' },
      ])
    ).toEqual(['x', 'y'])
  })
})

describe('API conversion', () => {
  it('round-trips keys, condition handles and config', () => {
    const apiNodes: WorkflowNode[] = [
      {
        id: 'n1',
        workflow_id: 'w',
        node_key: 'trigger_1',
        node_type: 'trigger',
        name: 'On resolve',
        ui_position: { x: 1, y: 2 },
        config: { trigger_type: 'finding_status_changed' },
        created_at: '',
      },
      {
        id: 'n2',
        workflow_id: 'w',
        node_key: 'cond',
        node_type: 'condition',
        name: 'Critical?',
        ui_position: { x: 1, y: 100 },
        config: { condition_expr: "finding.severity == 'critical'" },
        created_at: '',
      },
      {
        id: 'n3',
        workflow_id: 'w',
        node_key: 'scan',
        node_type: 'action',
        name: 'Verify',
        ui_position: { x: 1, y: 200 },
        config: { action_type: 'trigger_scan', action_config: { scan_id: 's1' } },
        created_at: '',
      },
    ]
    const apiEdges: WorkflowEdge[] = [
      {
        id: 'e1',
        workflow_id: 'w',
        source_node_key: 'trigger_1',
        target_node_key: 'cond',
        created_at: '',
      },
      {
        id: 'e2',
        workflow_id: 'w',
        source_node_key: 'cond',
        target_node_key: 'scan',
        source_handle: 'yes',
        created_at: '',
      },
    ]
    const g = fromApiGraph(apiNodes, apiEdges)
    const back = toApiGraph(g.nodes, g.edges)
    expect(back.nodes.map((x) => x.node_key)).toEqual(['trigger_1', 'cond', 'scan'])
    expect(back.nodes[2].config).toEqual({
      action_type: 'trigger_scan',
      action_config: { scan_id: 's1' },
    })
    expect(back.edges).toEqual([
      {
        source_node_key: 'trigger_1',
        target_node_key: 'cond',
        source_handle: undefined,
        label: undefined,
      },
      { source_node_key: 'cond', target_node_key: 'scan', source_handle: 'yes', label: undefined },
    ])
  })

  it('gives a new node an unused key', () => {
    const g = starterGraph()
    expect(nextNodeKey(g.nodes, 'trigger')).toBe('trigger_2')
    expect(nextNodeKey(g.nodes, 'action')).toBe('action_2')
  })
})

describe('offered types', () => {
  it('offers finding_status_changed and never run_script', () => {
    expect(WORKFLOW_TRIGGER_TYPES as readonly string[]).toContain('finding_status_changed')
    expect(WORKFLOW_ACTION_TYPES as readonly string[]).not.toContain('run_script')
  })
})
