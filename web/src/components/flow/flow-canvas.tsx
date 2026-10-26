'use client'

import * as React from 'react'
import {
  Background,
  BackgroundVariant,
  Handle,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type EdgeTypes,
  type Node,
  type NodeTypes,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Maximize2, Minus, Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { FlowEdge, FlowMarkers } from './flow-edge'
import { FLOW_KEYS, flowNeighbour } from './flow-keyboard'

/**
 * The graph kit's canvas (research/229 §4): a dotted grid, pan, zoom and fit,
 * no node dragging or connecting (a read-only view), and the keyboard model of
 * `flow-keyboard.ts` with one node in the tab order at a time. Nodes render a
 * `FlowNodeCard`, which reads the focus state from this canvas.
 *
 * The page owns what "active" means (which path to light up): the canvas only
 * reports the node that is hovered or focused, Enter on a node, and Escape.
 */

interface FlowFocusContextValue {
  /** The node in the tab order. */
  tabStop: string | null
  /** Moves the focus along the graph. */
  onNodeKeyDown: (id: string, e: React.KeyboardEvent<HTMLElement>) => void
  onNodeFocus: (id: string) => void
  onNodeBlur: () => void
  onNodeHover: (id: string | null) => void
  register: (id: string, el: HTMLElement | null) => void
}

const FlowFocusContext = React.createContext<FlowFocusContextValue | null>(null)

export function useFlowFocus(): FlowFocusContextValue | null {
  return React.useContext(FlowFocusContext)
}

export interface FlowCanvasProps<N extends Node, E extends Edge> {
  nodes: N[]
  edges: E[]
  nodeTypes: NodeTypes
  edgeTypes?: EdgeTypes
  /** The accessible name of the canvas ("Attack path graph"). */
  label: string
  /** Help text read with the canvas: what the keys do. */
  help: string
  /** The node hovered or focused, or null when the pointer and focus left. */
  onActiveChange?: (id: string | null) => void
  /** Enter on a node. */
  onOpen?: (id: string) => void
  /** Escape. */
  onClear?: () => void
  /** Extra keys for the page (path cycling), called before the graph keys. */
  onKey?: (e: React.KeyboardEvent<HTMLElement>) => boolean
  className?: string
  children?: React.ReactNode
}

const defaultEdgeTypes: EdgeTypes = { flow: FlowEdge }

function FlowControls() {
  const { t } = useTranslation()
  const rf = useReactFlow()
  const items = [
    { label: t('common.flow.zoomIn', 'Zoom in'), icon: Plus, run: () => void rf.zoomIn() },
    { label: t('common.flow.zoomOut', 'Zoom out'), icon: Minus, run: () => void rf.zoomOut() },
    {
      label: t('common.flow.fit', 'Fit view'),
      icon: Maximize2,
      run: () => void rf.fitView({ padding: 0.03, maxZoom: 1 }),
    },
  ]
  return (
    <Panel position="bottom-left" className="!m-3">
      <div className="flex flex-col overflow-hidden rounded-md border bg-card">
        {items.map(({ label, icon: Icon, run }) => (
          <Button
            key={label}
            type="button"
            variant="ghost"
            size="icon"
            className="size-8 rounded-none"
            aria-label={label}
            title={label}
            onClick={run}
          >
            <Icon className="size-4" aria-hidden />
          </Button>
        ))}
      </div>
    </Panel>
  )
}

function FlowCanvasInner<N extends Node, E extends Edge>({
  nodes,
  edges,
  nodeTypes,
  edgeTypes = defaultEdgeTypes,
  label,
  help,
  onActiveChange,
  onOpen,
  onClear,
  onKey,
  className,
  children,
}: FlowCanvasProps<N, E>) {
  const helpId = React.useId()
  const els = React.useRef(new Map<string, HTMLElement>())
  const focusable = React.useMemo(() => nodes.filter((n) => n.focusable !== false), [nodes])
  const [tabStop, setTabStop] = React.useState<string | null>(null)
  const stop =
    tabStop && focusable.some((n) => n.id === tabStop) ? tabStop : (focusable[0]?.id ?? null)
  const rf = useReactFlow()

  const keyNodes = React.useMemo(
    () => focusable.map((n) => ({ id: n.id, x: n.position.x, y: n.position.y })),
    [focusable]
  )
  const keyEdges = React.useMemo(
    () => edges.map((e) => ({ source: e.source, target: e.target })),
    [edges]
  )

  const value = React.useMemo<FlowFocusContextValue>(
    () => ({
      tabStop: stop,
      register: (id, el) => {
        if (el) els.current.set(id, el)
        else els.current.delete(id)
      },
      onNodeFocus: (id) => {
        setTabStop(id)
        onActiveChange?.(id)
        const n = focusable.find((x) => x.id === id)
        // Keep the focused node on screen when the graph is wider than the view.
        if (n) {
          const vp = rf.getViewport()
          const box = els.current.get(id)?.closest('.react-flow')?.getBoundingClientRect()
          if (box) {
            const sx = n.position.x * vp.zoom + vp.x
            const sy = n.position.y * vp.zoom + vp.y
            if (sx < 0 || sy < 0 || sx > box.width - 120 || sy > box.height - 60) {
              void rf.setCenter(n.position.x + 100, n.position.y + 40, { zoom: vp.zoom })
            }
          }
        }
      },
      onNodeBlur: () => onActiveChange?.(null),
      onNodeHover: (id) => onActiveChange?.(id),
      onNodeKeyDown: (id, e) => {
        if (onKey?.(e)) return
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onOpen?.(id)
          return
        }
        if (e.key === 'Escape') {
          e.preventDefault()
          onClear?.()
          ;(e.currentTarget as HTMLElement).blur()
          return
        }
        if (!FLOW_KEYS.has(e.key)) return
        e.preventDefault()
        const next = flowNeighbour(id, e.key, keyNodes, keyEdges)
        if (next) els.current.get(next)?.focus()
      },
    }),
    [stop, onActiveChange, onOpen, onClear, onKey, keyNodes, keyEdges, focusable, rf]
  )

  return (
    <FlowFocusContext.Provider value={value}>
      <div
        role="application"
        aria-roledescription={label}
        aria-label={label}
        aria-describedby={helpId}
        className={cn('relative h-full w-full', className)}
      >
        <p id={helpId} className="sr-only">
          {help}
        </p>
        <FlowMarkers />
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          nodesDraggable={false}
          nodesConnectable={false}
          nodesFocusable={false}
          edgesFocusable={false}
          elementsSelectable={false}
          // Node hover handlers also keep pointer events on read-only nodes.
          onNodeMouseEnter={(_, n) => onActiveChange?.(n.id)}
          onNodeMouseLeave={() => onActiveChange?.(null)}
          zoomOnScroll={false}
          preventScrolling={false}
          zoomOnDoubleClick={false}
          minZoom={0.3}
          maxZoom={1.5}
          fitView
          fitViewOptions={{ padding: 0.03, maxZoom: 1 }}
          proOptions={{ hideAttribution: true }}
          className="bg-transparent"
        >
          <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="var(--border)" />
          <FlowControls />
          {children}
        </ReactFlow>
      </div>
    </FlowFocusContext.Provider>
  )
}

export function FlowCanvas<N extends Node, E extends Edge>(props: FlowCanvasProps<N, E>) {
  return (
    <ReactFlowProvider>
      <FlowCanvasInner {...props} />
    </ReactFlowProvider>
  )
}

export type FlowNodeState = 'normal' | 'lit' | 'dim'

export interface FlowNodeCardProps {
  id: string
  /** The kind dot's colour class (`bg-info`) and the kind word. */
  kindDotClass: string
  kind: string
  /** Right side of the kind row (a type, a marker). */
  aside?: React.ReactNode
  title: React.ReactNode
  detail?: React.ReactNode
  footer?: React.ReactNode
  /**
   * What a screen reader reads after the node's visible text (its name comes
   * from the content, so what you see is what is announced).
   */
  description?: string
  state?: FlowNodeState
  /** Dashed edge: an alternative or a step outside the viewer's access. */
  dashed?: boolean
  /** Ports: a target handle on the left, a source handle on the right. */
  input?: boolean
  output?: boolean
  className?: string
}

/**
 * The node card of the graph kit: a kind row (a coloured dot and the kind word
 * in sentence case; no coloured border), the title, a one-line detail and a
 * footer of counts. The card is the focus stop of the canvas keyboard model.
 */
export function FlowNodeCard({
  id,
  kindDotClass,
  kind,
  aside,
  title,
  detail,
  footer,
  description,
  state = 'normal',
  dashed,
  input = true,
  output = true,
  className,
}: FlowNodeCardProps) {
  const focus = useFlowFocus()
  const register = focus?.register
  const ref = React.useCallback((el: HTMLDivElement | null) => register?.(id, el), [id, register])
  const descId = React.useId()
  return (
    <div
      ref={ref}
      role="button"
      tabIndex={focus ? (focus.tabStop === id ? 0 : -1) : 0}
      aria-describedby={description ? descId : undefined}
      data-testid="flow-node"
      data-node-id={id}
      data-state={state}
      onKeyDown={(e) => focus?.onNodeKeyDown(id, e)}
      onFocus={() => focus?.onNodeFocus(id)}
      onBlur={() => focus?.onNodeBlur()}
      onMouseEnter={() => focus?.onNodeHover(id)}
      onMouseLeave={() => focus?.onNodeHover(null)}
      className={cn(
        'w-[180px] rounded-md border bg-card text-left text-card-foreground transition-opacity outline-none focus-visible:ring-2 focus-visible:ring-ring',
        dashed && 'border-dashed',
        state === 'dim' && 'opacity-30',
        state === 'lit' && 'border-signal',
        className
      )}
    >
      {input && (
        <Handle
          type="target"
          position={Position.Left}
          isConnectable={false}
          className="!size-2 !border-border-strong !bg-card"
        />
      )}
      <div className="px-3 pt-2.5 pb-2">
        <div className="flex items-center justify-between gap-2 text-xs">
          <span className="flex min-w-0 items-center gap-1.5 font-medium">
            <span aria-hidden className={cn('size-2 shrink-0 rounded-sm', kindDotClass)} />
            <span className="truncate">{kind}</span>
          </span>{' '}
          {aside && <span className="shrink-0 text-muted-foreground">{aside}</span>}
        </div>{' '}
        <div className="mt-1 truncate text-sm font-semibold">{title}</div>{' '}
        {detail && <div className="truncate text-xs text-muted-foreground">{detail}</div>}
      </div>
      {footer && (
        <div className="flex items-center justify-between gap-2 border-t border-border-subtle px-3 py-1.5 text-xs text-muted-foreground tabular-nums">
          {footer}
        </div>
      )}
      {description && (
        <span id={descId} className="sr-only">
          {description}
        </span>
      )}
      {output && (
        <Handle
          type="source"
          position={Position.Right}
          isConnectable={false}
          className="!size-2 !border-border-strong !bg-card"
        />
      )}
    </div>
  )
}
