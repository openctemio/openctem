import type { Edge, Node } from '@xyflow/react'

import { wouldCreateCycle, type ConnectionVerdict } from '@/components/flow/connection-rules'
import type {
  CreateEdgeRequest,
  CreateNodeRequest,
  WorkflowEdge,
  WorkflowNode,
  WorkflowNodeConfig,
  WorkflowNodeType,
} from '@/lib/api/workflow-types'

/**
 * The Automations canvas graph: the React Flow view of a workflow, the
 * connection rule, the reachability check and the API conversion. The API
 * validates every save (cycle, unreachable node, edge into a trigger,
 * condition handles); these checks are the affordance.
 */

export interface AutomationNodeData extends Record<string, unknown> {
  label: string
  description?: string
  nodeKey: string
  config: WorkflowNodeConfig
}

export type AutomationNode = Node<AutomationNodeData>

/** A new workflow starts with one manual trigger, nothing else. */
export function starterGraph(): { nodes: AutomationNode[]; edges: Edge[] } {
  return {
    nodes: [
      {
        id: 'trigger_1',
        type: 'trigger',
        position: { x: 250, y: 50 },
        data: {
          label: 'Manual trigger',
          nodeKey: 'trigger_1',
          config: { trigger_type: 'manual' },
        },
      },
    ],
    edges: [],
  }
}

/** Default config of a node dropped on the canvas. */
export function defaultConfig(type: WorkflowNodeType): WorkflowNodeConfig {
  switch (type) {
    case 'trigger':
      return { trigger_type: 'manual' }
    case 'action':
      return { action_type: 'add_tags', action_config: { tags: [] } }
    case 'notification':
      return { notification_type: 'slack', notification_config: {} }
    default:
      return { condition_expr: '' }
  }
}

/** A node key not yet used on the canvas: <type>_<n>. */
export function nextNodeKey(nodes: AutomationNode[], type: string): string {
  const used = new Set(nodes.map((n) => n.data.nodeKey))
  let i = nodes.length + 1
  while (used.has(`${type}_${i}`)) i++
  return `${type}_${i}`
}

/**
 * Whether source -> target may be drawn: never into a trigger, never back
 * into itself, never closing a cycle (a run must end).
 */
export function automationConnectionRule(
  nodes: Pick<AutomationNode, 'id' | 'type'>[],
  edges: Pick<Edge, 'source' | 'target'>[]
): (source: string, target: string) => ConnectionVerdict {
  const types = new Map(nodes.map((n) => [n.id, n.type]))
  return (source, target) => {
    if (types.get(target) === 'trigger') {
      return { ok: false, reason: 'A trigger starts a run; nothing can lead into it.' }
    }
    if (wouldCreateCycle(edges, source, target)) {
      return { ok: false, reason: 'This connection would make a loop; a run must end.' }
    }
    return { ok: true }
  }
}

/** Ids of the nodes no trigger leads to (they would never run). */
export function unreachableNodes(
  nodes: Pick<AutomationNode, 'id' | 'type'>[],
  edges: Pick<Edge, 'source' | 'target'>[]
): string[] {
  const out = new Map<string, string[]>()
  for (const e of edges) out.set(e.source, [...(out.get(e.source) ?? []), e.target])
  const reached = new Set<string>()
  const stack = nodes.filter((n) => n.type === 'trigger').map((n) => n.id)
  for (const id of stack) reached.add(id)
  while (stack.length > 0) {
    const id = stack.pop()!
    for (const next of out.get(id) ?? []) {
      if (!reached.has(next)) {
        reached.add(next)
        stack.push(next)
      }
    }
  }
  return nodes.filter((n) => !reached.has(n.id)).map((n) => n.id)
}

/** A stored workflow as canvas nodes and edges. An empty one is the starter graph. */
export function fromApiGraph(
  nodes: WorkflowNode[] | undefined,
  edges: WorkflowEdge[] | undefined
): { nodes: AutomationNode[]; edges: Edge[] } {
  if (!nodes || nodes.length === 0) return starterGraph()
  const idByKey = new Map(nodes.map((n) => [n.node_key, n.id]))
  return {
    nodes: nodes.map((n) => ({
      id: n.id,
      type: n.node_type,
      position: { x: n.ui_position.x, y: n.ui_position.y },
      data: {
        label: n.name,
        description: n.description || '',
        nodeKey: n.node_key,
        config: n.config ?? {},
      },
    })),
    edges: (edges ?? []).map((e) => ({
      id: e.id,
      source: idByKey.get(e.source_node_key) ?? e.source_node_key,
      target: idByKey.get(e.target_node_key) ?? e.target_node_key,
      sourceHandle: e.source_handle || undefined,
      label: e.label || undefined,
    })),
  }
}

/** Canvas nodes and edges as the API's create/replace-graph body. */
export function toApiGraph(
  nodes: AutomationNode[],
  edges: Edge[]
): { nodes: CreateNodeRequest[]; edges: CreateEdgeRequest[] } {
  const keyById = new Map(nodes.map((n) => [n.id, n.data.nodeKey]))
  return {
    nodes: nodes.map((n) => ({
      node_key: n.data.nodeKey,
      node_type: n.type as WorkflowNodeType,
      name: n.data.label || n.data.nodeKey,
      description: n.data.description || undefined,
      ui_position: { x: n.position.x, y: n.position.y },
      config: n.data.config,
    })),
    edges: edges.map((e) => ({
      source_node_key: keyById.get(e.source) ?? e.source,
      target_node_key: keyById.get(e.target) ?? e.target,
      source_handle: e.sourceHandle || undefined,
      label: typeof e.label === 'string' ? e.label : undefined,
    })),
  }
}
