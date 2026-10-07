'use client'

import { useCallback, useMemo, useState } from 'react'
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
import { GitBranch, Mail, Play, Zap, type LucideIcon } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { makeIsValidConnection } from '@/components/flow/connection-rules'
import { cn } from '@/lib/utils'
import type { WorkflowNodeType } from '@/lib/api/workflow-types'
import {
  automationConnectionRule,
  defaultConfig,
  nextNodeKey,
  unreachableNodes,
  type AutomationNode,
  type AutomationNodeData,
} from '../lib/automation-graph'
import { AutomationInspector } from './automation-inspector'

interface Kind {
  type: WorkflowNodeType
  label: string
  icon: LucideIcon
  /** Theme-token classes: border, tint and handle. */
  border: string
  tint: string
  text: string
  handle: string
}

const KINDS: Kind[] = [
  {
    type: 'trigger',
    label: 'Trigger',
    icon: Zap,
    border: 'border-success',
    tint: 'bg-success/10',
    text: 'text-success',
    handle: '!bg-success',
  },
  {
    type: 'condition',
    label: 'Condition',
    icon: GitBranch,
    border: 'border-warning',
    tint: 'bg-warning/10',
    text: 'text-warning',
    handle: '!bg-warning',
  },
  {
    type: 'action',
    label: 'Action',
    icon: Play,
    border: 'border-info',
    tint: 'bg-info/10',
    text: 'text-info',
    handle: '!bg-info',
  },
  {
    type: 'notification',
    label: 'Notification',
    icon: Mail,
    border: 'border-primary',
    tint: 'bg-primary/10',
    text: 'text-primary',
    handle: '!bg-primary',
  },
]
const KIND = new Map(KINDS.map((k) => [k.type, k]))

function AutomationNodeView({ data, type, selected }: NodeProps<AutomationNode>) {
  const kind = KIND.get(type as WorkflowNodeType) ?? KINDS[2]
  const Icon = kind.icon
  return (
    <div
      className={cn(
        'min-w-[180px] rounded-lg border-2 bg-card p-3',
        kind.border,
        kind.tint,
        selected && 'ring-2 ring-ring'
      )}
    >
      {type !== 'trigger' && (
        <Handle type="target" position={Position.Top} className={cn('!h-3 !w-3', kind.handle)} />
      )}
      <div className="mb-1 flex items-center gap-2">
        <Icon className={cn('h-4 w-4', kind.text)} />
        <span className={cn('text-xs font-medium uppercase', kind.text)}>{kind.label}</span>
      </div>
      <p className="text-sm font-medium">{data.label}</p>
      {type === 'condition' ? (
        <>
          <Handle
            type="source"
            position={Position.Bottom}
            id="yes"
            className="!left-[30%] !h-3 !w-3 !bg-success"
          />
          <Handle
            type="source"
            position={Position.Bottom}
            id="no"
            className="!left-[70%] !h-3 !w-3 !bg-destructive"
          />
          <div className="mt-1 flex justify-between px-6 text-[10px] text-muted-foreground">
            <span>Yes</span>
            <span>No</span>
          </div>
        </>
      ) : (
        <Handle type="source" position={Position.Bottom} className={cn('!h-3 !w-3', kind.handle)} />
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

/**
 * The Automations canvas: a palette, the graph and an inspector for the
 * selected node. Connections into a trigger or closing a loop are refused
 * while dragging; nodes no trigger reaches are listed. The API checks the
 * same on save.
 */
export function AutomationCanvas({
  nodes,
  edges,
  setNodes,
  setEdges,
  onNodesChange,
  onEdgesChange,
}: {
  nodes: AutomationNode[]
  edges: Edge[]
  setNodes: (fn: (nds: AutomationNode[]) => AutomationNode[]) => void
  setEdges: (fn: (eds: Edge[]) => Edge[]) => void
  onNodesChange: OnNodesChange<AutomationNode>
  onEdgesChange: OnEdgesChange
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = nodes.find((n) => n.id === selectedId) ?? null

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
    (type: WorkflowNodeType, position = { x: 250, y: 80 + nodes.length * 110 }) => {
      setNodes((nds) => {
        const key = nextNodeKey(nds, type)
        return [
          ...nds,
          {
            id: key,
            type,
            position,
            data: { label: `New ${type}`, nodeKey: key, config: defaultConfig(type) },
          },
        ]
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

  return (
    <div className="flex h-[600px] border-t">
      <div className="w-56 shrink-0 space-y-2 border-e bg-muted/30 p-4">
        <h4 className="mb-2 font-medium">Add a step</h4>
        {KINDS.map((k) => (
          <button
            key={k.type}
            type="button"
            draggable
            onDragStart={(e) => {
              e.dataTransfer.setData('application/reactflow', k.type)
              e.dataTransfer.effectAllowed = 'move'
            }}
            onClick={() => addNode(k.type)}
            className={cn(
              'flex w-full items-center gap-3 rounded-lg border bg-card p-2.5 text-start text-sm font-medium hover:shadow-md',
              k.border
            )}
          >
            <k.icon className={cn('h-4 w-4', k.text)} />
            {k.label}
          </button>
        ))}
        <p className="pt-2 text-xs text-muted-foreground">
          Click or drag a step onto the canvas, then connect it from a handle. Select a step to set
          it up.
        </p>
      </div>

      <div
        className="min-w-0 flex-1"
        onDragOver={(e) => {
          e.preventDefault()
          e.dataTransfer.dropEffect = 'move'
        }}
        onDrop={(e) => {
          e.preventDefault()
          const type = e.dataTransfer.getData('application/reactflow') as WorkflowNodeType
          if (KIND.has(type)) {
            const rect = e.currentTarget.getBoundingClientRect()
            addNode(type, { x: e.clientX - rect.left, y: e.clientY - rect.top })
          }
        }}
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onConnectEnd={onConnectEnd}
          isValidConnection={isValidConnection}
          onSelectionChange={({ nodes: sel }) => setSelectedId(sel.length === 1 ? sel[0].id : null)}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ maxZoom: 1 }}
          className="bg-background"
        >
          <Background />
          <Controls />
        </ReactFlow>
      </div>

      <div className="w-72 shrink-0 space-y-3 overflow-y-auto border-s p-4">
        {unreachable.length > 0 && (
          <Alert>
            <AlertDescription className="text-xs">
              Not connected to a trigger, so they would never run: {unreachable.join(', ')}.
            </AlertDescription>
          </Alert>
        )}
        {selected ? (
          <AutomationInspector
            key={selected.id}
            node={selected}
            onChange={(d) => updateNode(selected.id, d)}
            onDelete={() => removeNode(selected.id)}
          />
        ) : (
          <p className="text-sm text-muted-foreground">Select a step to set it up.</p>
        )}
      </div>
    </div>
  )
}
