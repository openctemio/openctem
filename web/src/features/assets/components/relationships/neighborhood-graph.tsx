'use client'

/**
 * The asset neighborhood on the shared flow canvas (api
 * docs/architecture/asset-relationships.md, "Neighborhood"): the assets up
 * to 1-3 hops around an asset, its discovery lineage always drawn (root at
 * the top, the asset in the middle, what it exposes below), large
 * sibling groups as counted clusters. Selecting a node opens a panel to open
 * the asset, expand from it, or draw a cluster's members. The grouped list
 * stays the complete, accessible view.
 */

import * as React from 'react'
import type { Node, NodeProps } from '@xyflow/react'
import { ChevronRight, EyeOff, Layers } from 'lucide-react'
import { toast } from 'sonner'
import { FlowCanvas, FlowNodeCard, type FlowNodeState } from '@/components/flow/flow-canvas'
import type { FlowEdgeType } from '@/components/flow/flow-edge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { get } from '@/lib/api/client'
import { endpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import { cn } from '@/lib/utils'
import {
  fetchNodeNeighborhood,
  useAssetNeighborhood,
  type NeighborhoodDepth,
} from '../../hooks/use-asset-neighborhood'
import type { RelatedAssetsResponse } from '../../hooks/use-related-assets'
import { getAssetTypeLabel } from '../../lib/asset-type-icon'
import {
  buildNeighborhoodGraph,
  clusterType,
  graphTypes,
  layoutNeighborhood,
  mergeClusterPage,
  mergeExpansion,
  typeDotClass,
  type GraphNode,
  type NeighborhoodGraph,
} from '../../lib/neighborhood-graph'
import { relationVerbFallback, relationVerbKey } from '../../lib/relationship-verbs'

/** Rows drawn per "show more" of a cluster. */
const CLUSTER_PAGE = 50
const DEPTHS: NeighborhoodDepth[] = [1, 2, 3]

type GraphNodeData = { node: GraphNode; state: FlowNodeState }
type GraphFlowNode = Node<GraphNodeData, 'asset'>

function useGraphLabels() {
  const { t } = useTranslation()
  return React.useMemo(
    () => ({
      type: (type: string | undefined) =>
        type
          ? t(`assets.typeLabel.${type}`, getAssetTypeLabel(type))
          : t('assets.graph.asset', 'Asset'),
      verb: (type: string, direction: 'outgoing' | 'incoming') =>
        type === 'parent'
          ? direction === 'outgoing'
            ? t('assets.graph.parentOf', 'Parent of')
            : t('assets.graph.childOf', 'Child of')
          : t(relationVerbKey(type, direction), relationVerbFallback(type, direction)),
      hiddenTitle: t('assets.lineage.hidden', 'Hidden asset'),
      hiddenDetail: t('assets.graph.hiddenDetail', 'Outside your data scope'),
      hiddenCount: (n: number) =>
        t('assets.graph.hiddenNeighbors', '{n} outside your access', { n }),
      clusterTitle: (n: number) => t('assets.graph.clusterTitle', '{n} assets', { n }),
      mixed: t('assets.graph.mixedTypes', 'Several types'),
      thisAsset: t('assets.graph.thisAsset', 'This asset'),
      root: t('assets.graph.root', 'Root'),
    }),
    [t]
  )
}

function GraphNodeView({ data, id }: NodeProps<GraphFlowNode>) {
  const labels = useGraphLabels()
  const n = data.node
  if (n.kind === 'hidden') {
    return (
      <FlowNodeCard
        id={id}
        kindDotClass="bg-muted-foreground"
        kind={labels.hiddenTitle}
        aside={n.root ? labels.root : <EyeOff className="size-3.5" aria-hidden />}
        title={labels.hiddenTitle}
        detail={labels.hiddenDetail}
        state={data.state}
        vertical
        dashed
      />
    )
  }
  if (n.kind === 'cluster') {
    const only = clusterType(n)
    return (
      <FlowNodeCard
        id={id}
        kindDotClass={only ? typeDotClass(only) : 'bg-muted-foreground'}
        kind={only ? labels.type(only) : labels.mixed}
        aside={<Layers className="size-3.5" aria-hidden />}
        title={labels.clusterTitle(n.remaining)}
        detail={labels.verb(n.relType, n.direction)}
        state={data.state}
        vertical
      />
    )
  }
  return (
    <FlowNodeCard
      id={id}
      kindDotClass={typeDotClass(n.type)}
      kind={labels.type(n.type)}
      aside={
        n.self ? (
          <span className="font-medium text-foreground">{labels.thisAsset}</span>
        ) : n.root ? (
          labels.root
        ) : undefined
      }
      title={<span title={n.name}>{n.name}</span>}
      footer={
        n.hiddenNeighbors > 0 ? <span>{labels.hiddenCount(n.hiddenNeighbors)}</span> : undefined
      }
      state={data.state}
      vertical
      className={cn(n.self && 'border-foreground')}
    />
  )
}

const nodeTypes = { asset: GraphNodeView }

export interface NeighborhoodGraphViewProps {
  assetId: string
  /** Opens a related asset; the sheet keeps the back trail. */
  onNavigateToAsset?: (assetId: string, name: string) => void
  className?: string
}

export function NeighborhoodGraphView({
  assetId,
  onNavigateToAsset,
  className,
}: NeighborhoodGraphViewProps) {
  const { t } = useTranslation()
  const labels = useGraphLabels()
  const [depth, setDepth] = React.useState<NeighborhoodDepth>(2)
  const { data, error, isLoading, mutate } = useAssetNeighborhood(assetId, depth)

  // The drawn graph: the answer, then every expansion merged into it. A new
  // answer (another asset, another depth) starts over.
  const [state, setState] = React.useState<{ from: unknown; graph: NeighborhoodGraph } | null>(null)
  const graph = React.useMemo(() => {
    if (!data) return null
    return state?.from === data ? state.graph : buildNeighborhoodGraph(data)
  }, [data, state])
  const update = React.useCallback(
    (fn: (g: NeighborhoodGraph) => NeighborhoodGraph) => {
      if (!data) return
      setState((cur) => {
        const base = cur?.from === data ? cur.graph : buildNeighborhoodGraph(data)
        return { from: data, graph: fn(base) }
      })
    },
    [data]
  )

  const [selected, setSelected] = React.useState<string | null>(null)
  const [active, setActive] = React.useState<string | null>(null)
  const [busy, setBusy] = React.useState(false)
  React.useEffect(() => {
    setSelected(null)
  }, [assetId, depth])

  const placed = React.useMemo(() => (graph ? layoutNeighborhood(graph) : []), [graph])
  const focusId = active ?? selected
  const near = React.useMemo(() => {
    if (!graph || !focusId) return null
    const ids = new Set<string>([focusId])
    for (const e of graph.edges.values()) {
      if (e.source === focusId) ids.add(e.target)
      if (e.target === focusId) ids.add(e.source)
    }
    return ids
  }, [graph, focusId])

  const nodes = React.useMemo<GraphFlowNode[]>(() => {
    if (!graph) return []
    return placed.map((p) => {
      const node = graph.nodes.get(p.id) as GraphNode
      const state: FlowNodeState = near
        ? near.has(p.id)
          ? p.id === focusId
            ? 'lit'
            : 'normal'
          : 'dim'
        : 'normal'
      return { id: p.id, type: 'asset', position: { x: p.x, y: p.y }, data: { node, state } }
    })
  }, [graph, placed, near, focusId])

  const edges = React.useMemo<FlowEdgeType[]>(() => {
    if (!graph) return []
    return [...graph.edges.values()]
      .filter((e) => graph.nodes.has(e.source) && graph.nodes.has(e.target))
      .map((e) => {
        const touches = focusId != null && (e.source === focusId || e.target === focusId)
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: 'flow',
          data: {
            state: focusId && !touches ? 'dim' : e.lineage ? 'hot' : 'flow',
            label: touches || (e.lineage && !focusId) ? labels.verb(e.type, 'outgoing') : undefined,
          },
        }
      })
  }, [graph, focusId, labels])

  const selectedNode = selected && graph ? graph.nodes.get(selected) : undefined

  const expandNode = React.useCallback(
    async (id: string) => {
      setBusy(true)
      try {
        const res = await fetchNodeNeighborhood(id)
        update((g) => mergeExpansion(g, res))
      } catch (err) {
        toast.error(
          getErrorMessage(err, t('assets.graph.expandFailed', 'Could not load the related assets'))
        )
      } finally {
        setBusy(false)
      }
    },
    [update, t]
  )

  const expandCluster = React.useCallback(
    async (id: string) => {
      const c = graph?.nodes.get(id)
      if (c?.kind !== 'cluster') return
      setBusy(true)
      try {
        const q = new URLSearchParams({
          type: c.relType,
          direction: c.direction,
          limit: String(CLUSTER_PAGE),
          offset: String(c.offset),
        })
        const res = await get<RelatedAssetsResponse>(
          endpoints.assets.relationshipGroups(c.anchor, q.toString())
        )
        const group = res.groups.find((g) => g.type === c.relType && g.direction === c.direction)
        update((g) => mergeClusterPage(g, id, group?.items ?? [], group?.total ?? 0))
        if (!group || group.total <= c.offset + group.items.length) setSelected(null)
      } catch (err) {
        toast.error(
          getErrorMessage(err, t('assets.graph.expandFailed', 'Could not load the related assets'))
        )
      } finally {
        setBusy(false)
      }
    },
    [graph, update, t]
  )

  const legend = React.useMemo(() => (graph ? graphTypes(graph) : []), [graph])
  const lineagePath = React.useMemo(() => {
    const chain = [...(data?.lineage?.nodes ?? [])].sort((a, b) => b.depth - a.depth)
    return chain.length > 1 ? chain : []
  }, [data])

  const assetCount = graph ? [...graph.nodes.values()].filter((n) => n.kind === 'asset').length : 0
  const hidden = graph
    ? [...graph.nodes.values()].reduce(
        (sum, n) => sum + (n.kind === 'asset' ? n.hiddenNeighbors : 0),
        0
      )
    : 0

  return (
    <div className={cn('space-y-3', className)}>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="flex items-center gap-2">
          <span id="nb-depth-label" className="text-xs text-muted-foreground">
            {t('assets.graph.depth', 'Hops')}
          </span>
          <div
            role="group"
            aria-labelledby="nb-depth-label"
            className="inline-flex rounded-md border p-0.5"
          >
            {DEPTHS.map((d) => (
              <Button
                key={d}
                type="button"
                size="sm"
                variant={depth === d ? 'secondary' : 'ghost'}
                className="h-7 min-w-8 px-2 tabular-nums"
                aria-pressed={depth === d}
                onClick={() => setDepth(d)}
              >
                {d}
              </Button>
            ))}
          </div>
        </div>
        {legend.length > 0 && (
          <ul
            aria-label={t('assets.graph.legend', 'Asset types')}
            className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground"
          >
            {legend.map((type) => (
              <li key={type} className="flex items-center gap-1.5">
                <span aria-hidden className={cn('size-2 rounded-sm', typeDotClass(type))} />
                {labels.type(type)}
              </li>
            ))}
          </ul>
        )}
        {graph && (
          <p className="ml-auto text-xs text-muted-foreground tabular-nums" aria-live="polite">
            {t('assets.graph.summary', '{n} assets shown', { n: assetCount })}
            {hidden > 0 ? `, ${labels.hiddenCount(hidden)}` : ''}
          </p>
        )}
      </div>

      {lineagePath.length > 0 && (
        <nav aria-label={t('assets.graph.lineageLabel', 'Where this asset comes from')}>
          <ol className="flex flex-wrap items-center gap-1 text-xs">
            <li aria-hidden className="mr-1 text-muted-foreground">
              {t('assets.graph.lineageLabel', 'Where this asset comes from')}
            </li>
            {lineagePath.map((n, i) => (
              <li key={n.depth} className="flex items-center gap-1">
                {i > 0 && <ChevronRight className="size-3 text-muted-foreground" aria-hidden />}
                {n.hidden ? (
                  <span className="text-muted-foreground">{labels.hiddenTitle}</span>
                ) : n.depth === 0 ? (
                  <span className="font-medium" aria-current="true">
                    {n.name}
                  </span>
                ) : (
                  <button
                    type="button"
                    className="rounded-sm font-medium underline-offset-2 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                    onClick={() => n.id && onNavigateToAsset?.(n.id, n.name ?? '')}
                  >
                    {n.name}
                  </button>
                )}
              </li>
            ))}
          </ol>
        </nav>
      )}

      {isLoading && !graph ? (
        <Skeleton className="h-[420px] w-full" />
      ) : error ? (
        <ErrorState
          title={t('assets.graph.errorTitle', 'related assets')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : graph ? (
        <div className="h-[360px] overflow-hidden rounded-md border sm:h-[480px]" aria-busy={busy}>
          <FlowCanvas
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            label={t('assets.graph.canvasLabel', 'Related assets graph')}
            help={t(
              'assets.graph.canvasHelp',
              'Arrow keys move between related assets, Enter selects one, Escape clears the selection. The list view shows every relationship.'
            )}
            onActiveChange={setActive}
            onOpen={setSelected}
            onNodeClick={setSelected}
            fitKey={nodes.length}
            onClear={() => setSelected(null)}
          />
        </div>
      ) : null}

      {graph?.truncated && (
        <p className="text-xs text-muted-foreground">
          {t(
            'assets.graph.truncated',
            'Not every related asset fits: the rest are counted in groups. Lower the hops or expand one asset at a time.'
          )}
        </p>
      )}

      <div aria-live="polite">
        {selectedNode && (
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border bg-muted/30 px-3 py-2 text-sm">
            <div className="min-w-0">
              {selectedNode.kind === 'asset' ? (
                <>
                  <div className="truncate font-medium">{selectedNode.name}</div>
                  <div className="text-xs text-muted-foreground">
                    {labels.type(selectedNode.type)}
                    {selectedNode.hiddenNeighbors > 0
                      ? `, ${labels.hiddenCount(selectedNode.hiddenNeighbors)}`
                      : ''}
                  </div>
                </>
              ) : selectedNode.kind === 'cluster' ? (
                <>
                  <div className="font-medium">{labels.clusterTitle(selectedNode.remaining)}</div>
                  <div className="text-xs text-muted-foreground">
                    {labels.verb(selectedNode.relType, selectedNode.direction)}
                  </div>
                </>
              ) : (
                <>
                  <div className="font-medium">{labels.hiddenTitle}</div>
                  <div className="text-xs text-muted-foreground">{labels.hiddenDetail}</div>
                </>
              )}
            </div>
            <div className="flex shrink-0 gap-2">
              {selectedNode.kind === 'asset' && !selectedNode.expanded && (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => void expandNode(selectedNode.id)}
                >
                  {t('assets.graph.expand', 'Show related assets')}
                </Button>
              )}
              {selectedNode.kind === 'cluster' && (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => void expandCluster(selectedNode.id)}
                >
                  {selectedNode.remaining > CLUSTER_PAGE
                    ? t('assets.graph.showSome', 'Show {n}', { n: CLUSTER_PAGE })
                    : t('assets.graph.showAll', 'Show all')}
                </Button>
              )}
              {selectedNode.kind === 'asset' && !selectedNode.self && (
                <Button
                  size="sm"
                  onClick={() => onNavigateToAsset?.(selectedNode.id, selectedNode.name)}
                >
                  {t('assets.graph.open', 'Open asset')}
                </Button>
              )}
            </div>
          </div>
        )}
      </div>

      <p className="text-xs text-muted-foreground">
        {t(
          'assets.related.graphHint',
          'The list is the complete, accessible view; the graph draws the same relationships around this asset.'
        )}
      </p>
    </div>
  )
}
