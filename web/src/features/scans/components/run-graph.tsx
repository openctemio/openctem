'use client'

import { memo, useMemo } from 'react'
import useSWR from 'swr'
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

import { Badge } from '@/components/ui/badge'
import { layeredLayout } from '@/components/flow/layered-layout'
import { TruncatedText } from '@/features/shared'
import { get } from '@/lib/api/client'
import { scanWorkflowEndpoints, scanRunEndpoints } from '@/lib/api/endpoints'
import type { RunStage, RunStageList } from '@/lib/api/generated'
import type { ScanWorkflow, StepRun } from '@/lib/api'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { useCapabilityTable } from '@/features/scan-workflows/lib/use-capability-table'
import { skipLabel, skippedReasons } from './run-stage-lanes'

/** What one node of the run overlay shows. Every number comes from the API. */
export interface RunGraphNode {
  key: string
  name: string
  status: string
  tool?: string
  capability?: string
  findings: number
  error?: string
  lane?: RunStage
}

/** Status tone: success, running, failure, or neutral. */
export function statusTone(status: string): 'ok' | 'run' | 'bad' | 'idle' {
  switch (status) {
    case 'completed':
      return 'ok'
    case 'running':
    case 'queued':
      return 'run'
    case 'failed':
    case 'timeout':
      return 'bad'
    case 'partial':
      return 'bad'
    default:
      return 'idle'
  }
}

/**
 * The run overlay's nodes and edges: one node per step run (the run's own
 * record: key, name, tool, capability), with its stage lane's counts;
 * edges from the workflow's dependencies where both steps are in the run.
 */
export function runGraphModel(
  stepRuns: StepRun[],
  lanes: RunStage[],
  dependsOn: Record<string, string[]>
): { nodes: RunGraphNode[]; edges: Array<{ source: string; target: string }> } {
  const byKey = new Map(lanes.map((l) => [l.stage_key ?? '', l]))
  const nodes = stepRuns.map<RunGraphNode>((sr) => ({
    key: sr.step_key,
    name: sr.step_name || sr.step_key,
    status: sr.status,
    tool: sr.tool,
    capability: sr.capability,
    findings: sr.findings_count ?? 0,
    error: sr.error_message,
    lane: byKey.get(sr.step_key),
  }))
  const keys = new Set(nodes.map((n) => n.key))
  const edges: Array<{ source: string; target: string }> = []
  for (const n of nodes) {
    for (const dep of dependsOn[n.key] ?? []) {
      if (keys.has(dep)) edges.push({ source: dep, target: n.key })
    }
  }
  return { nodes, edges }
}

type OverlayNode = Node<{ node: RunGraphNode; label: string }, 'runstep'>

const RunStepNode = memo(function RunStepNode({ data }: NodeProps<OverlayNode>) {
  const n = data.node
  const tone = statusTone(n.status)
  const reasons = skippedReasons(n.lane?.skipped)
  return (
    <div
      className={cn(
        'w-60 rounded-lg border bg-card p-2 text-xs shadow-sm',
        tone === 'ok' && 'border-success',
        tone === 'run' && 'border-info',
        tone === 'bad' && 'border-destructive'
      )}
      data-testid="run-graph-node"
    >
      <Handle type="target" position={Position.Top} isConnectable={false} />
      <div className="flex items-center gap-1.5">
        <span className="truncate font-medium">{data.label}</span>
        <Badge variant="outline" className="ms-auto px-1 py-0 text-[10px]">
          {n.status}
        </Badge>
      </div>
      <div className="mt-0.5 flex flex-wrap items-center gap-1 text-muted-foreground">
        {n.capability && <span className="font-mono text-[10px]">{n.capability}</span>}
        {n.tool && <TruncatedText value={n.tool} label="Tool" className="max-w-[120px]" />}
      </div>
      {n.lane && (
        <div className="mt-1 tabular-nums">
          in {n.lane.inputs ?? 0} → planned {n.lane.planned ?? 0}
          {n.findings > 0 && <span className="ms-2">findings {n.findings}</span>}
        </div>
      )}
      {!n.lane && n.findings > 0 && <div className="mt-1 tabular-nums">findings {n.findings}</div>}
      {(n.lane?.chunks?.total ?? 0) > 1 && (
        <div className="mt-0.5 tabular-nums text-muted-foreground" data-testid="run-graph-chunks">
          chunks {n.lane!.chunks!.completed ?? 0}/{n.lane!.chunks!.total} on{' '}
          {n.lane!.sensors?.length ?? 0} sensor(s)
        </div>
      )}
      {reasons.length > 0 && (
        <ul className="mt-1 flex flex-wrap gap-1" aria-label="Skipped targets by reason">
          {reasons.slice(0, 3).map(([reason, count]) => (
            <li key={reason} className="rounded border px-1 text-[10px] text-muted-foreground">
              {count} {skipLabel(reason)}
            </li>
          ))}
        </ul>
      )}
      {n.error && (
        <p className="mt-1 line-clamp-2 break-words text-destructive" dir="auto">
          {toDisplayText(n.error)}
        </p>
      )}
      <Handle type="source" position={Position.Bottom} isConnectable={false} />
    </div>
  )
})

const nodeTypes = { runstep: RunStepNode }

/**
 * The run overlay: the workflow graph of a run, read-only, each step with
 * its status, counts, skip reasons and error. Data: the run's step runs,
 * GET /scan-runs/{id}/stages and the workflow's dependencies.
 */
export function RunGraph({
  runId,
  workflowId,
  stepRuns,
  refreshInterval,
}: {
  runId: string
  workflowId?: string
  stepRuns: StepRun[]
  refreshInterval?: number
}) {
  const { table } = useCapabilityTable()
  const { data: lanes } = useSWR<RunStageList>(
    scanRunEndpoints.stages(runId),
    (url: string) => get<RunStageList>(url),
    { revalidateOnFocus: false, refreshInterval }
  )
  const { data: workflow } = useSWR<ScanWorkflow>(
    workflowId ? scanWorkflowEndpoints.get(workflowId) : null,
    (url: string) => get<ScanWorkflow>(url),
    { revalidateOnFocus: false }
  )

  const { nodes, edges } = useMemo(() => {
    const deps: Record<string, string[]> = {}
    for (const s of workflow?.steps ?? []) deps[s.step_key] = s.depends_on ?? []
    const model = runGraphModel(stepRuns, lanes?.data ?? [], deps)
    // Top to bottom: the overlay lives in a narrow side sheet.
    const pos = layeredLayout(
      model.nodes.map((n) => n.key),
      model.edges,
      { direction: 'TB', columnWidth: 270, rowHeight: 150 }
    )
    const names = new Map(table.capabilities.map((c) => [c.id, c.name]))
    const flowNodes: OverlayNode[] = model.nodes.map((n) => ({
      id: n.key,
      type: 'runstep',
      position: pos[n.key],
      data: { node: n, label: n.name || names.get(n.capability ?? '') || n.key },
      draggable: false,
      connectable: false,
    }))
    const flowEdges: Edge[] = model.edges.map((e) => ({
      id: `${e.source}->${e.target}`,
      source: e.source,
      target: e.target,
      markerEnd: { type: MarkerType.ArrowClosed },
    }))
    return { nodes: flowNodes, edges: flowEdges }
  }, [stepRuns, lanes, workflow, table])

  return (
    <div className="h-[28rem] w-full rounded-md border" aria-label="Workflow of this run">
      <ReactFlowProvider>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          // The sheet animates open: fit again once it has its size.
          onInit={(rf) => setTimeout(() => void rf.fitView({ padding: 0.15 }), 300)}
          minZoom={0.3}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </ReactFlowProvider>
    </div>
  )
}
