'use client'

import * as React from 'react'
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react'
import { Crown, Globe, Zap } from 'lucide-react'
import {
  FlowCanvas,
  FlowNodeCard,
  useFlowFocus,
  type FlowNodeState,
} from '@/components/flow/flow-canvas'
import type { FlowEdgeType } from '@/components/flow/flow-edge'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { AttackPathDetail, PathNode } from '../hooks/use-attack-path-detail'
import {
  INTERNET,
  focusSets,
  formatWeight,
  layoutPaths,
  nodeByKey,
  stepText,
  type Focus,
} from '../lib/attack-path-model'
import { useAttackPathLabels } from './attack-path-labels'

type StepNodeData = { node: PathNode; state: FlowNodeState; alt: boolean }
type InternetNodeData = { state: FlowNodeState }
type StepFlowNode = Node<StepNodeData, 'step'>
type InternetFlowNode = Node<InternetNodeData, 'internet'>

/** The kind dot of each role: entry in the caution tone (public exposure), hop blue, target ink. */
export const ROLE_DOT: Record<PathNode['role'], string> = {
  entry: 'bg-st-accepted-fg',
  hop: 'bg-info',
  target: 'bg-foreground',
}

function StepNode({ data, id }: NodeProps<StepFlowNode>) {
  const { t } = useTranslation()
  const labels = useAttackPathLabels()
  const n = data.node
  if (n.hidden) {
    return (
      <FlowNodeCard
        id={id}
        kindDotClass={ROLE_DOT[n.role]}
        kind={labels.role(n)}
        title={labels.hiddenTitle}
        detail={t('prioritization.attackPath.hiddenDetail', 'No details in your scope')}
        description={labels.nodeDescription(n)}
        state={data.state}
        dashed
        output={n.role !== 'target'}
      />
    )
  }
  return (
    <FlowNodeCard
      id={id}
      kindDotClass={ROLE_DOT[n.role]}
      kind={labels.role(n)}
      aside={
        n.role === 'target' ? (
          <span className="inline-flex items-center gap-1 font-medium text-foreground">
            {n.isCrownJewel && <Crown className="size-3" aria-hidden />}
            {n.criticality ? t(`criticality.${n.criticality}`, n.criticality) : null}
          </span>
        ) : n.role === 'entry' ? (
          <Globe
            className="size-3.5"
            role="img"
            aria-label={t('prioritization.attackPath.internetFacing', 'Internet-facing')}
          />
        ) : undefined
      }
      title={n.name}
      detail={labels.assetType(n.assetType)}
      footer={
        <>
          <span>
            {t('prioritization.attackPath.findingsCount', 'Findings {n}', { n: n.openFindings })}
          </span>
          <span className={cn(n.kevFindings > 0 && 'font-medium text-tone-danger-fg')}>
            {t('prioritization.attackPath.kevCount', 'KEV {n}', { n: n.kevFindings })}
          </span>
        </>
      }
      description={labels.nodeDescription(n)}
      state={data.state}
      dashed={data.alt}
      output={n.role !== 'target'}
    />
  )
}

function InternetNode({ data, id }: NodeProps<InternetFlowNode>) {
  const { t } = useTranslation()
  const focus = useFlowFocus()
  return (
    <div
      data-testid="flow-internet"
      onMouseEnter={() => focus?.onNodeHover(id)}
      onMouseLeave={() => focus?.onNodeHover(null)}
      className={cn(
        'flex items-center gap-1.5 text-xs font-medium text-muted-foreground transition-opacity',
        data.state === 'dim' && 'opacity-30'
      )}
    >
      <Globe className="size-3.5" aria-hidden />
      {t('prioritization.attackPath.internet', 'Internet')}
      <Handle
        type="source"
        position={Position.Right}
        isConnectable={false}
        className="!opacity-0"
      />
    </div>
  )
}

const nodeTypes = { step: StepNode, internet: InternetNode }

/** The chip on an edge: the enabling finding, its weight and KEV, as separate parts. */
function StepLabel({ text, weight, kev }: { text: string; weight: string; kev: boolean }) {
  const { t } = useTranslation()
  return (
    <span className="flex items-center gap-1.5" title={text}>
      {kev && (
        <Zap
          className="size-3 shrink-0"
          aria-label={t('prioritization.attackPath.kev', 'KEV')}
          role="img"
        />
      )}
      <span className="max-w-[112px] truncate">{text}</span>
      <span className="font-medium tabular-nums">{weight}</span>
    </span>
  )
}

export interface AttackPathCanvasProps {
  detail: AttackPathDetail
  shown: number[]
  /** The selected route: its edges are drawn hot, the others as alternatives. */
  selected: number
  focus: Focus
  onFocusChange: (focus: Focus) => void
  onOpenNode: (key: string) => void
  onCyclePath: (delta: 1 | -1) => void
}

export function AttackPathCanvas({
  detail,
  shown,
  selected,
  focus,
  onFocusChange,
  onOpenNode,
  onCyclePath,
}: AttackPathCanvasProps) {
  const { t } = useTranslation()
  const labels = useAttackPathLabels()
  const layout = React.useMemo(() => layoutPaths(detail, shown), [detail, shown])
  const lit = React.useMemo(() => focusSets(layout, detail, focus), [layout, detail, focus])
  const byKey = React.useMemo(() => nodeByKey(detail), [detail])
  const selectedNodes = React.useMemo(
    () => new Set(detail.paths[selected]?.nodes ?? []),
    [detail, selected]
  )

  const nodes = React.useMemo<(StepFlowNode | InternetFlowNode)[]>(
    () =>
      layout.nodes.map((l) => {
        const state: FlowNodeState = lit ? (lit.nodes.has(l.key) ? 'lit' : 'dim') : 'normal'
        if (l.key === INTERNET) {
          return {
            id: l.key,
            type: 'internet',
            position: { x: l.x, y: l.y + 40 },
            data: { state },
            focusable: false,
          }
        }
        return {
          id: l.key,
          type: 'step',
          position: { x: l.x, y: l.y },
          data: {
            node: byKey.get(l.key)!,
            state,
            alt: shown.length > 1 && !selectedNodes.has(l.key),
          },
        }
      }),
    [layout, lit, byKey, shown.length, selectedNodes]
  )

  // Every edge into a node carries that node's lead finding, so the label is
  // drawn once per node: on the edge of the selected path, else the first one.
  const labelled = React.useMemo(() => {
    const primary = new Map<string, string>()
    for (const e of layout.edges) {
      const cur = primary.get(e.to)
      if (
        !cur ||
        (e.paths.includes(selected) &&
          !layout.edges.find((x) => x.id === cur)?.paths.includes(selected))
      ) {
        primary.set(e.to, e.id)
      }
    }
    return new Set(primary.values())
  }, [layout, selected])

  const edges = React.useMemo<FlowEdgeType[]>(
    () =>
      layout.edges.map((e) => {
        const target = byKey.get(e.to)
        const onSelected = e.paths.includes(selected)
        const state = lit
          ? lit.edges.has(e.id)
            ? 'hot'
            : 'dim'
          : onSelected
            ? 'hot'
            : shown.length > 1
              ? 'alt'
              : 'flow'
        const text = stepText(target)
        return {
          id: e.id,
          source: e.from,
          target: e.to,
          type: 'flow',
          data: {
            state,
            weight: target?.weight ?? undefined,
            danger: target?.finding?.kev === true,
            // A step with no open finding has no label: the score card and
            // the node say "assumed".
            label:
              target?.hidden || !text || !labelled.has(e.id) ? undefined : (
                <StepLabel
                  text={text}
                  weight={formatWeight(target?.weight)}
                  kev={target?.finding?.kev === true}
                />
              ),
          },
        }
      }),
    [layout, byKey, lit, selected, shown.length, labelled]
  )

  const onKey = React.useCallback(
    (e: React.KeyboardEvent<HTMLElement>) => {
      if (e.key === ']' || e.key === '[') {
        e.preventDefault()
        onCyclePath(e.key === ']' ? 1 : -1)
        return true
      }
      return false
    },
    [onCyclePath]
  )

  return (
    <FlowCanvas
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      label={t('prioritization.attackPath.canvasLabel', 'Attack path graph')}
      help={labels.canvasHelp}
      onActiveChange={(id) => onFocusChange(id ? { kind: 'node', key: id } : null)}
      onOpen={onOpenNode}
      onClear={() => onFocusChange(null)}
      onKey={onKey}
    />
  )
}
