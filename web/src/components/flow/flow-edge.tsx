'use client'

import type * as React from 'react'
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  type Edge,
  type EdgeProps,
} from '@xyflow/react'
import { cn } from '@/lib/utils'

/**
 * The one edge of every flow canvas (research/229 §4.1): a bezier with an
 * arrow at the target and an optional label chip. Width follows the weight
 * (1 to 6 px, square-root scale) so volume or likelihood reads as thickness,
 * never as speed. States:
 * - `flow`: the default;
 * - `hot`: on the selected path (signal colour, animated dashes unless the
 *   person asked for reduced motion);
 * - `alt`: an alternative to the selected path (dotted, lighter);
 * - `dim`: outside the hovered or focused path (30 % opacity).
 */
export type FlowEdgeState = 'flow' | 'hot' | 'alt' | 'dim'

export type FlowEdgeData = {
  label?: React.ReactNode
  /** 0 to 1; maps to the stroke width. */
  weight?: number
  state?: FlowEdgeState
  /** The label in the danger colour (a known exploited step). */
  danger?: boolean
}

export type FlowEdgeType = Edge<FlowEdgeData, 'flow'>

export function flowStrokeWidth(weight: number | undefined): number {
  if (typeof weight !== 'number' || !Number.isFinite(weight)) return 1.5
  const w = Math.min(1, Math.max(0, weight))
  return Math.round((1 + 5 * Math.sqrt(w)) * 10) / 10
}

export const FLOW_MARKER_ID = 'flow-arrow'
export const FLOW_MARKER_HOT_ID = 'flow-arrow-hot'

/** Arrow markers, rendered once per canvas. */
export function FlowMarkers() {
  return (
    <svg aria-hidden className="absolute h-0 w-0">
      <defs>
        {[
          [FLOW_MARKER_ID, 'var(--border-strong)'],
          [FLOW_MARKER_HOT_ID, 'var(--signal)'],
        ].map(([id, fill]) => (
          <marker
            key={id}
            id={id}
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="10"
            markerHeight="10"
            markerUnits="userSpaceOnUse"
            orient="auto"
          >
            <path d="M0 0 L8 4 L0 8 z" fill={fill} />
          </marker>
        ))}
      </defs>
    </svg>
  )
}

export function FlowEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
}: EdgeProps<FlowEdgeType>) {
  const state = data?.state ?? 'flow'
  const [path, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX: targetX - 4,
    targetY,
    targetPosition,
  })
  const hot = state === 'hot'
  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={`url(#${hot ? FLOW_MARKER_HOT_ID : FLOW_MARKER_ID})`}
        className={cn('flow-edge', `flow-edge-${state}`)}
        style={{
          stroke: hot ? 'var(--signal)' : 'var(--border-strong)',
          strokeWidth: flowStrokeWidth(data?.weight),
        }}
      />
      {data?.label != null && (
        <EdgeLabelRenderer>
          <div
            data-testid="flow-edge-label"
            data-state={state}
            className={cn(
              'nodrag nopan pointer-events-none absolute rounded border bg-card px-1.5 py-0.5 text-xs whitespace-nowrap transition-opacity',
              data.danger
                ? 'border-tone-danger-fg/40 text-tone-danger-fg'
                : 'text-muted-foreground',
              state === 'dim' && 'opacity-30',
              state === 'alt' && 'opacity-60'
            )}
            style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
          >
            {data.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}
