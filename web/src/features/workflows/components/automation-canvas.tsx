'use client'

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  addEdge,
  type Connection,
  type Edge,
  type NodeProps,
  type OnEdgesChange,
  type OnNodesChange,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Plus } from 'lucide-react'
import { toast } from 'sonner'

import { useTranslation } from '@/context/i18n-provider'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { makeIsValidConnection } from '@/components/flow/connection-rules'
import { cn } from '@/lib/utils'
import type { WorkflowCatalog, WorkflowNodeType } from '@/lib/api/workflow-types'
import {
  automationConnectionRule,
  defaultConfig,
  nextNodeKey,
  unreachableNodes,
  type AutomationNode,
  type AutomationNodeData,
} from '../lib/automation-graph'
import {
  catalogEntriesFor,
  unlistedTypeOf,
  skippedEntries,
  type StepCount,
} from '../lib/automation-lifecycle'
import { useAutomationLabels } from '../lib/use-automation-labels'
import { AutomationInspector } from './automation-inspector'
import { StepGlyph } from './step-glyph'

const KIND_LABEL: Record<WorkflowNodeType, [string, string]> = {
  trigger: ['automations.canvas.kindTrigger', 'Trigger'],
  condition: ['automations.canvas.kindCondition', 'Condition'],
  action: ['automations.canvas.kindAction', 'Action'],
  notification: ['automations.canvas.kindNotification', 'Notification'],
}
const KINDS = Object.keys(KIND_LABEL) as WorkflowNodeType[]
const asKind = (type: string | undefined): WorkflowNodeType =>
  type && type in KIND_LABEL ? (type as WorkflowNodeType) : 'action'

interface CanvasContextValue {
  catalog?: WorkflowCatalog
  /** Per-step counts from a preview, a run or recorded simulate runs. */
  counts: Map<string, StepCount> | null
}
const CanvasContext = createContext<CanvasContextValue>({ counts: null })

/** The counts line of a step: in, out and the largest skipped reasons. */
export function StepCounts({ count, kind }: { count: StepCount; kind: string }) {
  const { t } = useTranslation()
  const labels = useAutomationLabels()
  const skipped = skippedEntries(count.skipped).slice(0, 2)
  return (
    <div className="mt-2 space-y-0.5 border-t pt-1.5 text-xs" data-testid="step-counts">
      <div className="flex justify-between gap-3 tabular-nums">
        <span>
          {kind === 'trigger'
            ? t('automations.counts.inNone', 'in —')
            : t('automations.counts.in', 'in {n}', { n: count.in })}
        </span>
        <span>{t('automations.counts.out', 'out {n}', { n: count.out })}</span>
      </div>
      {skipped.map(([reason, n]) => (
        <div key={reason} className="text-muted-foreground">
          {t('automations.counts.skipped', '{n} {reason}', {
            n,
            reason: labels.skipReason(reason),
          })}
        </div>
      ))}
    </div>
  )
}

/** "Removed type: <id>" for a stored step the catalog no longer offers. */
function RemovedTypeLine({ id }: { id: string }) {
  const { t } = useTranslation()
  return (
    <p className="mt-1 text-xs text-warning" data-testid="removed-type">
      {t('automations.removedTypePrefix', 'Removed type:')} <span className="font-mono">{id}</span>
    </p>
  )
}

function AutomationNodeView({ data, type, selected }: NodeProps<AutomationNode>) {
  const { t } = useTranslation()
  const { catalog, counts } = useContext(CanvasContext)
  const kind = asKind(type)
  const removed = unlistedTypeOf(catalog, kind, data.config)
  const count = counts?.get(data.nodeKey)
  return (
    <div
      className={cn(
        'min-w-[200px] max-w-[260px] rounded-lg border bg-card p-3 text-card-foreground shadow-xs',
        selected && 'ring-2 ring-brand ring-offset-1 ring-offset-background'
      )}
    >
      {kind !== 'trigger' && (
        <Handle type="target" position={Position.Top} className="!h-2.5 !w-2.5 !bg-foreground/60" />
      )}
      <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
        <StepGlyph kind={kind} />
        {t(KIND_LABEL[kind][0], KIND_LABEL[kind][1])}
      </div>
      <p className="text-sm font-medium">{data.label}</p>
      {removed && <RemovedTypeLine id={removed} />}
      {count && <StepCounts count={count} kind={kind} />}
      {kind === 'condition' ? (
        <>
          <Handle
            type="source"
            position={Position.Bottom}
            id="yes"
            className="!left-[30%] !h-2.5 !w-2.5 !bg-foreground/60"
          />
          <Handle
            type="source"
            position={Position.Bottom}
            id="no"
            className="!left-[70%] !h-2.5 !w-2.5 !bg-foreground/60"
          />
          <div className="mt-1 flex justify-between px-6 text-[10px] text-muted-foreground">
            <span>{t('automations.canvas.yes', 'Yes')}</span>
            <span>{t('automations.canvas.no', 'No')}</span>
          </div>
        </>
      ) : (
        <Handle
          type="source"
          position={Position.Bottom}
          className="!h-2.5 !w-2.5 !bg-foreground/60"
        />
      )}
    </div>
  )
}

const nodeTypes = {
  trigger: AutomationNodeView,
  condition: AutomationNodeView,
  action: AutomationNodeView,
  notification: AutomationNodeView,
}

/** Steps in run order (breadth first from the triggers), unreachable ones last. */
function orderedSteps(
  nodes: AutomationNode[],
  edges: Edge[]
): { node: AutomationNode; depth: number }[] {
  const out = new Map<string, string[]>()
  for (const e of edges) out.set(e.source, [...(out.get(e.source) ?? []), e.target])
  const depth = new Map<string, number>()
  const queue = nodes.filter((n) => n.type === 'trigger').map((n) => n.id)
  for (const id of queue) depth.set(id, 0)
  while (queue.length > 0) {
    const id = queue.shift()!
    for (const next of out.get(id) ?? []) {
      if (!depth.has(next)) {
        depth.set(next, (depth.get(id) ?? 0) + 1)
        queue.push(next)
      }
    }
  }
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const reached = [...depth.entries()].map(([id, d]) => ({ node: byId.get(id)!, depth: d }))
  const rest = nodes.filter((n) => !depth.has(n.id)).map((node) => ({ node, depth: 0 }))
  return [...reached.filter((s) => s.node), ...rest]
}

/** The phone layout of the graph: steps as an indented list in run order. */
function StepList({
  nodes,
  edges,
  selectedId,
  onSelect,
}: {
  nodes: AutomationNode[]
  edges: Edge[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  const { t } = useTranslation()
  const { catalog, counts } = useContext(CanvasContext)
  const steps = useMemo(() => orderedSteps(nodes, edges), [nodes, edges])
  return (
    <ol className="space-y-2 p-3" aria-label={t('automations.canvas.stepsList', 'Steps')}>
      {steps.map(({ node, depth }) => {
        const kind = asKind(node.type)
        const removed = unlistedTypeOf(catalog, kind, node.data.config)
        const count = counts?.get(node.data.nodeKey)
        return (
          <li key={node.id} style={{ marginInlineStart: `${Math.min(depth, 4) * 12}px` }}>
            <button
              type="button"
              onClick={() => onSelect(node.id)}
              aria-pressed={selectedId === node.id}
              className={cn(
                'w-full rounded-lg border bg-card p-3 text-start',
                selectedId === node.id && 'ring-2 ring-brand'
              )}
            >
              <span className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                <StepGlyph kind={kind} />
                {t(KIND_LABEL[kind][0], KIND_LABEL[kind][1])}
              </span>
              <span className="mt-0.5 block text-sm font-medium break-words">
                {node.data.label}
              </span>
              {removed && <RemovedTypeLine id={removed} />}
              {count && <StepCounts count={count} kind={kind} />}
            </button>
          </li>
        )
      })}
    </ol>
  )
}

interface PaletteItem {
  kind: WorkflowNodeType
  type?: string
  label: string
  allowed: boolean
  permission?: string
}

/** The step palette, built from the catalog alone (plus the condition step). */
function Palette({
  catalog,
  loading,
  disabled,
  onAdd,
}: {
  catalog?: WorkflowCatalog
  loading: boolean
  disabled: boolean
  onAdd: (item: PaletteItem) => void
}) {
  const { t } = useTranslation()
  const labels = useAutomationLabels()
  const [query, setQuery] = useState('')
  const groups = useMemo(() => {
    const name = (kind: WorkflowNodeType, type: string) =>
      kind === 'trigger'
        ? labels.trigger(type)
        : kind === 'action'
          ? labels.action(type)
          : labels.notification(type)
    const q = query.trim().toLowerCase()
    return KINDS.map((kind) => {
      const items: PaletteItem[] =
        kind === 'condition'
          ? [{ kind, label: t('automations.canvas.kindCondition', 'Condition'), allowed: true }]
          : catalogEntriesFor(catalog, kind).map((e) => ({
              kind,
              type: e.type,
              label: name(kind, e.type),
              allowed: e.allowed,
              permission: e.permission,
            }))
      return { kind, items: q ? items.filter((i) => i.label.toLowerCase().includes(q)) : items }
    })
  }, [catalog, labels, query, t])

  return (
    <div className="space-y-3" data-testid="automation-palette">
      <Input
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder={t('automations.canvas.findStep', 'Find a step')}
        aria-label={t('automations.canvas.findStep', 'Find a step')}
        className="h-8"
      />
      {loading && (
        <p className="text-xs text-muted-foreground">
          {t('automations.canvas.loadingCatalog', 'Loading steps…')}
        </p>
      )}
      {groups.map((g) =>
        g.items.length === 0 ? null : (
          <div
            key={g.kind}
            role="group"
            aria-label={t(KIND_LABEL[g.kind][0], KIND_LABEL[g.kind][1])}
          >
            <h4 className="mb-1 flex items-center justify-between text-sm font-medium">
              {t(KIND_LABEL[g.kind][0], KIND_LABEL[g.kind][1])}
              <span className="text-xs font-normal text-muted-foreground tabular-nums">
                {g.items.length}
              </span>
            </h4>
            <ul className="space-y-0.5">
              {g.items.map((item) => {
                const off = disabled || !item.allowed
                return (
                  <li key={`${item.kind}:${item.type ?? ''}`}>
                    <button
                      type="button"
                      draggable={!off}
                      disabled={off}
                      data-testid={`palette-${item.kind}-${item.type ?? 'condition'}`}
                      onDragStart={(e) => {
                        e.dataTransfer.setData(
                          'application/reactflow',
                          `${item.kind}:${item.type ?? ''}`
                        )
                        e.dataTransfer.effectAllowed = 'move'
                      }}
                      onClick={() => onAdd(item)}
                      className="flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-start text-sm hover:bg-muted disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:bg-transparent"
                    >
                      <StepGlyph kind={item.kind} className="mt-0.5" />
                      <span className="min-w-0">
                        <span className="block break-words">{item.label}</span>
                        {!item.allowed && (
                          <span className="block text-xs text-muted-foreground">
                            {item.permission
                              ? t('automations.canvas.needsPermission', 'Needs {permission}', {
                                  permission: item.permission,
                                })
                              : t('automations.canvas.notAllowed', 'Not allowed for you')}
                          </span>
                        )}
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
          </div>
        )
      )}
      <p className="text-xs text-muted-foreground">
        {t(
          'automations.canvas.paletteHint',
          'Click or drag a step onto the canvas, then connect it from a handle. Steps you lack permission for are listed with the reason.'
        )}
      </p>
    </div>
  )
}

/**
 * The Automations canvas: a palette built from the catalog, the graph (a
 * list below 900px) and an inspector for the selected step. Connections into
 * a trigger or closing a loop are refused while dragging; steps no trigger
 * reaches are listed. The API checks the same on save and on validate.
 */
export function AutomationCanvas({
  nodes,
  edges,
  setNodes,
  setEdges,
  onNodesChange,
  onEdgesChange,
  catalog,
  catalogLoading = false,
  readOnly = false,
  counts = null,
  focusRequest = null,
  sidePanel,
}: {
  nodes: AutomationNode[]
  edges: Edge[]
  setNodes: (fn: (nds: AutomationNode[]) => AutomationNode[]) => void
  setEdges: (fn: (eds: Edge[]) => Edge[]) => void
  onNodesChange: OnNodesChange<AutomationNode>
  onEdgesChange: OnEdgesChange
  catalog?: WorkflowCatalog
  catalogLoading?: boolean
  /** The viewer may not edit the draft: no palette, no inspector edits. */
  readOnly?: boolean
  counts?: Map<string, StepCount> | null
  /** Select the step with this node key (a validate problem was clicked). */
  focusRequest?: { nodeKey: string; seq: number } | null
  /** Panels shown under the inspector (checks, before going live). */
  sidePanel?: React.ReactNode
}) {
  const { t } = useTranslation()
  const labels = useAutomationLabels()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const selected = nodes.find((n) => n.id === selectedId) ?? null

  const focusKey = focusRequest?.nodeKey
  const focusSeq = focusRequest?.seq
  // The latest graph, read (not subscribed to) when a request arrives: only a
  // new request moves the selection, not every graph edit.
  const nodesRef = useRef(nodes)
  const setNodesRef = useRef(setNodes)
  useEffect(() => {
    nodesRef.current = nodes
    setNodesRef.current = setNodes
  }, [nodes, setNodes])
  useEffect(() => {
    if (!focusKey) return
    const target = nodesRef.current.find((n) => n.data.nodeKey === focusKey)
    if (!target) return
    setSelectedId(target.id)
    setNodesRef.current((nds) => nds.map((n) => ({ ...n, selected: n.id === target.id })))
  }, [focusKey, focusSeq])

  const { isValidConnection, lastRefusal } = useMemo(
    () => makeIsValidConnection(automationConnectionRule(nodes, edges)),
    [nodes, edges]
  )
  const onConnect = useCallback(
    (c: Connection) =>
      setEdges((eds) =>
        addEdge(
          {
            ...c,
            label: c.sourceHandle === 'no' ? 'No' : c.sourceHandle === 'yes' ? 'Yes' : undefined,
          },
          eds
        )
      ),
    [setEdges]
  )
  const onConnectEnd = useCallback(() => {
    const r = lastRefusal()
    if (r) toast.error(r.reason)
  }, [lastRefusal])

  const unreachable = useMemo(() => {
    const ids = new Set(unreachableNodes(nodes, edges))
    return nodes.filter((n) => ids.has(n.id)).map((n) => n.data.label)
  }, [nodes, edges])

  const addNode = useCallback(
    (
      kind: WorkflowNodeType,
      type: string | undefined,
      label: string,
      position = { x: 250, y: 80 + nodes.length * 110 }
    ) => {
      setNodes((nds) => {
        const key = nextNodeKey(nds, kind)
        const config = defaultConfig(kind)
        if (type && kind === 'trigger') config.trigger_type = type
        if (type && kind === 'action') config.action_type = type
        if (type && kind === 'notification') config.notification_type = type
        return [...nds, { id: key, type: kind, position, data: { label, nodeKey: key, config } }]
      })
    },
    [nodes.length, setNodes]
  )

  const updateNode = (id: string, data: AutomationNodeData) =>
    setNodes((nds) => nds.map((n) => (n.id === id ? { ...n, data } : n)))
  const removeNode = (id: string) => {
    setNodes((nds) => nds.filter((n) => n.id !== id))
    setEdges((eds) => eds.filter((e) => e.source !== id && e.target !== id))
    setSelectedId(null)
  }

  const ctx = useMemo(() => ({ catalog, counts }), [catalog, counts])

  return (
    <CanvasContext.Provider value={ctx}>
      <div className="flex flex-col border-t min-[900px]:h-[640px] min-[900px]:flex-row">
        {!readOnly && (
          <div className="shrink-0 border-b bg-muted/30 p-3 min-[900px]:w-60 min-[900px]:overflow-y-auto min-[900px]:border-e min-[900px]:border-b-0">
            <Button
              variant="outline"
              size="sm"
              className="w-full min-[900px]:hidden"
              aria-expanded={paletteOpen}
              onClick={() => setPaletteOpen((o) => !o)}
            >
              <Plus className="me-2 h-4 w-4" />
              {t('automations.canvas.addStep', 'Add a step')}
            </Button>
            <div
              className={cn('mt-3 min-[900px]:mt-0 min-[900px]:block', !paletteOpen && 'hidden')}
            >
              <Palette
                catalog={catalog}
                loading={catalogLoading}
                disabled={readOnly}
                onAdd={(item) => {
                  addNode(item.kind, item.type, item.label)
                  setPaletteOpen(false)
                }}
              />
            </div>
          </div>
        )}

        <div className="min-[900px]:hidden">
          <StepList
            nodes={nodes}
            edges={edges}
            selectedId={selectedId}
            onSelect={(id) => setSelectedId(id)}
          />
        </div>

        <div
          className="hidden min-w-0 flex-1 min-[900px]:block"
          onDragOver={(e) => {
            e.preventDefault()
            e.dataTransfer.dropEffect = 'move'
          }}
          onDrop={(e) => {
            e.preventDefault()
            if (readOnly) return
            const [kind, type] = e.dataTransfer.getData('application/reactflow').split(':', 2)
            if (!KINDS.includes(kind as WorkflowNodeType)) return
            const entry = catalogEntriesFor(catalog, kind).find((x) => x.type === type)
            if (kind !== 'condition' && (!entry || !entry.allowed)) return
            const rect = e.currentTarget.getBoundingClientRect()
            const label =
              kind === 'trigger'
                ? labels.trigger(type)
                : kind === 'action'
                  ? labels.action(type)
                  : kind === 'notification'
                    ? labels.notification(type)
                    : t('automations.canvas.kindCondition', 'Condition')
            addNode(kind as WorkflowNodeType, type || undefined, label, {
              x: e.clientX - rect.left,
              y: e.clientY - rect.top,
            })
          }}
        >
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={readOnly ? undefined : onEdgesChange}
            onConnect={readOnly ? undefined : onConnect}
            onConnectEnd={onConnectEnd}
            isValidConnection={isValidConnection}
            nodesConnectable={!readOnly}
            onSelectionChange={({ nodes: sel }) =>
              setSelectedId(sel.length === 1 ? sel[0].id : null)
            }
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ maxZoom: 1 }}
            className="bg-background"
          >
            <Background />
            <Controls />
          </ReactFlow>
        </div>

        <div className="shrink-0 space-y-3 border-t p-4 min-[900px]:w-80 min-[900px]:overflow-y-auto min-[900px]:border-s min-[900px]:border-t-0">
          {unreachable.length > 0 && (
            <Alert>
              <AlertDescription className="text-xs">
                {t(
                  'automations.canvas.unreachable',
                  'Not connected to a trigger, so they would never run: {names}.',
                  { names: unreachable.join(', ') }
                )}
              </AlertDescription>
            </Alert>
          )}
          {selected ? (
            <AutomationInspector
              key={selected.id}
              node={selected}
              catalog={catalog}
              readOnly={readOnly}
              onChange={(d) => updateNode(selected.id, d)}
              onDelete={() => removeNode(selected.id)}
            />
          ) : (
            <p className="text-sm text-muted-foreground">
              {t('automations.canvas.selectStep', 'Select a step to set it up.')}
            </p>
          )}
          {sidePanel}
        </div>
      </div>
    </CanvasContext.Provider>
  )
}
