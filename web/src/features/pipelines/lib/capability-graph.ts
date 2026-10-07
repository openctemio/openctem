/**
 * The scan workflow builder's view of the capability catalog
 * (GET /api/v1/scans/stages): which ports a step has, whether two steps may
 * be connected, and the adapter step that would connect them.
 *
 * Affordance only: these lookups read the served table and never decide
 * more than the API does. Every save is validated by the API
 * (stage.ValidateGraph), and POST /pipelines/verify reports the same
 * issues while editing.
 */

import type { components } from '@/lib/api/generated/api.types'
import {
  type ConnectionVerdict,
  type FlowEdgeLike,
  wouldCreateCycle,
} from '@/components/flow/connection-rules'
import type { PipelineStep } from '@/lib/api'
import { generateStepKey, generateTempStepId } from '@/lib/utils'

type S = components['schemas']
export type ScanStageList = S['internal_infra_http_handler.ScanStageListResponse']
export type GraphValidation = S['internal_infra_http_handler.PipelineGraphValidationResponse']
export type GraphIssue = S['internal_infra_http_handler.PipelineGraphIssueResponse']

/** One standard param of a capability contract. */
export interface CapabilityParam {
  name: string
  type: 'string' | 'string_list' | 'integer' | 'boolean' | 'port_list'
  description: string
  enum: string[]
  min?: number
  max?: number
}

/** One capability as the builder uses it. */
export interface Capability {
  key: string
  id: string
  name: string
  tier: string
  available: boolean
  crossCutting: boolean
  inPorts: string[]
  outPorts: string[]
  tools: string[]
  defaultTool: string
  params: CapabilityParam[]
  /** Standard param name -> tool config key, per tool. */
  toolParams: Record<string, Record<string, string>>
}

export interface Adapter {
  from: string
  to: string
  capability: string
}

export interface CapabilityTable {
  capabilities: Capability[]
  adapters: Adapter[]
  portLabels: Record<string, string>
}

export const EMPTY_TABLE: CapabilityTable = { capabilities: [], adapters: [], portLabels: {} }

/** Normalizes the served catalog (every generated field is optional). */
export function toCapabilityTable(list: ScanStageList | undefined): CapabilityTable {
  if (!list) return EMPTY_TABLE
  const capabilities: Capability[] = (list.stages ?? []).map((s) => {
    const impls = s.implementations ?? []
    const tools = impls.map((i) => i.tool ?? '').filter(Boolean)
    return {
      key: s.key ?? '',
      id: s.id ?? s.key ?? '',
      name: s.name ?? s.key ?? '',
      tier: s.tier ?? 'T1',
      available: s.available ?? tools.length > 0,
      crossCutting: s.cross_cutting ?? false,
      inPorts: s.in_ports ?? [],
      outPorts: s.out_ports ?? [],
      tools,
      defaultTool: impls.find((i) => i.default)?.tool ?? tools[0] ?? '',
      params: (s.params ?? []).map((p) => ({
        name: p.name ?? '',
        type: p.type ?? 'string',
        description: p.description ?? '',
        enum: p.enum ?? [],
        min: p.min,
        max: p.max,
      })),
      toolParams: Object.fromEntries(impls.map((i) => [i.tool ?? '', i.params ?? {}])),
    }
  })
  const adapters: Adapter[] = (list.adapters ?? []).map((a) => ({
    from: a.from ?? '',
    to: a.to ?? '',
    capability: a.capability ?? '',
  }))
  const portLabels: Record<string, string> = {}
  for (const p of list.port_types ?? []) {
    if (p.type) portLabels[p.type] = p.label ?? p.type
  }
  return { capabilities, adapters, portLabels }
}

/**
 * The capability a step runs, as the API places it: its tool when the tool
 * implements exactly one routed capability, else the capability its words
 * name. Null for a step the catalog cannot place (a tenant tool): such a
 * step has no ports and takes no data from its predecessors.
 */
export function capabilityForStep(
  table: CapabilityTable,
  step: Pick<PipelineStep, 'tool' | 'capabilities'>
): Capability | null {
  const words = (step.capabilities ?? []).map((c) => c.toLowerCase().trim())
  const byWord = table.capabilities.find((c) => words.includes(c.key))
  const tool = (step.tool ?? '').toLowerCase().trim()
  if (tool) {
    const routed = table.capabilities.filter((c) => c.available && c.tools.includes(tool))
    if (routed.length === 1) return routed[0]
    if (byWord && byWord.tools.includes(tool)) return byWord
    return null
  }
  return byWord ?? null
}

function adapterBetween(
  table: CapabilityTable,
  from: Capability,
  to: Capability
): Capability | null {
  for (const out of from.outPorts) {
    for (const inp of to.inPorts) {
      const a = table.adapters.find((x) => x.from === out && x.to === inp)
      const cap = a && table.capabilities.find((c) => c.key === a.capability)
      if (cap) return cap
    }
  }
  return null
}

function portList(table: CapabilityTable, ports: string[]): string {
  return ports.map((p) => table.portLabels[p] ?? p).join(', ')
}

/**
 * Whether source → target may be wired: no cycle, and the source gives a
 * port type the target takes. A step without a contract can be wired (it
 * only orders the two) with a warning. A refusal names the adapter step
 * that would connect the two when the catalog has one.
 */
export function checkStepConnection(
  table: CapabilityTable,
  steps: PipelineStep[],
  edges: FlowEdgeLike[],
  sourceId: string,
  targetId: string
): ConnectionVerdict {
  const source = steps.find((s) => s.id === sourceId)
  const target = steps.find((s) => s.id === targetId)
  if (!source || !target) return { ok: false, reason: 'Connect two steps of this workflow.' }
  if (wouldCreateCycle(edges, sourceId, targetId)) {
    return {
      ok: false,
      reason: `${target.name} already runs before ${source.name}: this connection would make a loop.`,
    }
  }
  const from = capabilityForStep(table, source)
  const to = capabilityForStep(table, target)
  if (!from || !to) {
    const opaque = !from ? source : target
    return {
      ok: true,
      warning: `${opaque.name} has no typed ports: the connection only orders the two steps and passes no data.`,
    }
  }
  if (to.tier === 'T2') {
    return {
      ok: false,
      reason: `${to.name} is intrusive (T2): it runs only on the scan's own targets and is never fed by another step.`,
    }
  }
  if (from.outPorts.some((p) => to.inPorts.includes(p))) return { ok: true }
  const adapter = adapterBetween(table, from, to)
  const base = `${target.name} takes ${portList(table, to.inPorts)}, but ${source.name} gives ${portList(table, from.outPorts)}.`
  if (adapter) {
    return {
      ok: false,
      reason: `${base} Insert ${adapter.name} between them.`,
      adapter: adapter.key,
    }
  }
  return { ok: false, reason: base }
}

/** Edges between steps (dependencies), as source/target step ids. */
export function stepEdges(steps: PipelineStep[]): FlowEdgeLike[] {
  const byKey = new Map(steps.map((s) => [s.step_key, s.id]))
  const edges: FlowEdgeLike[] = []
  for (const s of steps) {
    for (const dep of s.depends_on ?? []) {
      const src = byKey.get(dep)
      if (src) edges.push({ source: src, target: s.id })
    }
  }
  return edges
}

/**
 * Inserts the adapter capability between source and target: a new step
 * (the capability's default tool) that depends on source, and target
 * depends on the new step instead of source.
 */
export function insertAdapterStep(
  table: CapabilityTable,
  steps: PipelineStep[],
  sourceId: string,
  targetId: string,
  capabilityKey: string
): PipelineStep[] {
  const cap = table.capabilities.find((c) => c.key === capabilityKey)
  const source = steps.find((s) => s.id === sourceId)
  const target = steps.find((s) => s.id === targetId)
  if (!cap || !source || !target) return steps
  // generateStepKey adds a random suffix, so the key is new in this workflow.
  const key = generateStepKey(cap.defaultTool || cap.key)
  const sp = source.ui_position ?? { x: 0, y: 0 }
  const tp = target.ui_position ?? { x: sp.x + 400, y: sp.y }
  const adapter: PipelineStep = {
    id: generateTempStepId(),
    step_key: key,
    name: cap.name,
    description: '',
    order: steps.length + 1,
    node_type: 'scanner',
    tool: cap.defaultTool,
    // The tool is pinned: the server derives its capabilities from it.
    capabilities: [],
    timeout_seconds: 3600,
    depends_on: [source.step_key],
    ui_position: { x: (sp.x + tp.x) / 2, y: (sp.y + tp.y) / 2 + 120 },
    max_retries: 0,
    retry_delay_seconds: 0,
  }
  return [
    ...steps.map((s) =>
      s.id === targetId
        ? {
            ...s,
            depends_on: [...(s.depends_on ?? []).filter((d) => d !== source.step_key), key],
          }
        : s
    ),
    adapter,
  ]
}

/** Issues of a graph check that point at one step (by step key). */
export function issuesForStep(report: GraphValidation | null, stepKey: string): GraphIssue[] {
  if (!report) return []
  return (report.errors ?? []).filter((e) => e.node === stepKey || e.to === stepKey)
}
