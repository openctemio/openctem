'use client'

import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  useStore,
  type Edge,
  type EdgeProps,
  type ReactFlowState,
} from '@xyflow/react'
import { cn } from '@/lib/utils'
import type { EdgeDescription } from '../lib/capability-graph'

/**
 * A connection between two steps of the scan workflow builder, labelled
 * with what it carries: the port types that pass (as the node chips write
 * them), "order only" when a step has no typed ports, or why nothing can
 * pass. The line style follows the state; the label always says it in words,
 * so the meaning never depends on colour. Below half zoom the label is left
 * out (unreadable); the edge's accessible name keeps the full sentence.
 */

export type DataFlowEdgeData = { description?: EdgeDescription | null }
export type DataFlowEdgeType = Edge<DataFlowEdgeData, 'dataFlow'>

/** Stroke colour per state (theme tokens: light and dark). */
const STROKE: Record<EdgeDescription['flow']['state'], string> = {
  data: 'var(--info)',
  order: 'var(--muted-foreground)',
  invalid: 'var(--destructive)',
}

/** Zoom below which labels are hidden. */
export const EDGE_LABEL_MIN_ZOOM = 0.5

const zoomedOutSelector = (s: ReactFlowState) => s.transform[2] < EDGE_LABEL_MIN_ZOOM

export function DataFlowEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
  selected,
  data,
}: EdgeProps<DataFlowEdgeType>) {
  const [path, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
  })
  const zoomedOut = useStore(zoomedOutSelector)
  const d = data?.description ?? null
  const state = d?.flow.state ?? 'data'

  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        interactionWidth={16}
        style={{
          stroke: STROKE[state],
          strokeWidth: selected ? 2.5 : state === 'order' ? 1.25 : 1.5,
        }}
      />
      {d && !zoomedOut && (
        <EdgeLabelRenderer>
          <div
            aria-hidden
            title={d.text}
            data-edge-state={state}
            style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
            className={cn(
              'nodrag nopan pointer-events-auto absolute max-w-[180px] truncate rounded-full border bg-background px-1.5 py-px text-[10px] leading-4 whitespace-nowrap shadow-xs',
              state === 'data' && 'border-info/40 font-mono text-foreground',
              state === 'order' && 'border-dashed text-muted-foreground italic',
              state === 'invalid' && 'border-destructive/60 text-destructive',
              selected && 'ring-2 ring-ring'
            )}
          >
            {d.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}
