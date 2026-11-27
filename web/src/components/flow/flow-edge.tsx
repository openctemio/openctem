'use client'

import type * as React from 'react'
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  Position,
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
  /**
   * Points the edge passes through (flow coordinates), for an edge that
   * skips a column: the layout reserves an empty slot there so the line
   * never crosses a node, and the label sits on the middle point.
   */
  via?: { x: number; y: number }[]
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

/**
 * A left-to-right path through waypoints: one horizontal-tangent bezier per
 * leg, so it reads like the plain edges, with the label on the middle
 * waypoint. Returns [path, labelX, labelY].
 */
export function viaPath(
  from: { x: number; y: number },
  via: readonly { x: number; y: number }[],
  to: { x: number; y: number }
): [string, number, number] {
  const pts = [from, ...via, to]
  let d = `M${from.x},${from.y}`
  for (let i = 1; i < pts.length; i++) {
    const a = pts[i - 1]
    const b = pts[i]
    const mx = (a.x + b.x) / 2
    d += ` C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`
  }
  const mid = via[Math.floor((via.length - 1) / 2)]
  return [d, mid.x, mid.y]
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
  // Stop just short of the target handle so the arrow head shows.
  const fromTop = targetPosition === Position.Top
  const end = { x: fromTop ? targetX : targetX - 4, y: fromTop ? targetY - 4 : targetY }
  const [path, labelX, labelY] =
    data?.via && data.via.length > 0 && !fromTop
      ? viaPath({ x: sourceX, y: sourceY }, data.via, end)
      : getBezierPath({
          sourceX,
          sourceY,
          sourcePosition,
          targetX: end.x,
          targetY: end.y,
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
