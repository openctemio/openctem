'use client'

/**
 * Bounded dependency graph of one asset: layered left to right from the
 * direct packages, vulnerable packages and the paths that bring them in
 * highlighted, searchable, and a tree list for phones and screen readers.
 */

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Search } from 'lucide-react'
import Link from '@/components/link'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { SegmentedLens } from '@/features/shared'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { SEVERITY_CHART_COLORS, SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'
import type { DependencyGraph as Graph, GraphNode } from '../api/types'

const COL_W = 220
const ROW_H = 44
const NODE_W = 180
const NODE_H = 32

function worstSeverity(n: GraphNode): keyof GraphNode['vulnerabilities'] | null {
  for (const s of SEVERITY_LEVELS) if (s !== 'info' && n.vulnerabilities[s] > 0) return s
  return null
}

export interface LaidOutNode extends GraphNode {
  layer: number
  row: number
}

/** Layer per node: its depth when known, else breadth-first from the roots. */
export function layoutGraph(graph: Graph): { nodes: LaidOutNode[]; layers: number; rows: number } {
  const children = new Map<string, string[]>()
  const parents = new Map<string, string[]>()
  for (const e of graph.edges) {
    children.set(e.from, [...(children.get(e.from) ?? []), e.to])
    parents.set(e.to, [...(parents.get(e.to) ?? []), e.from])
  }
  const layer = new Map<string, number>()
  const queue: string[] = []
  for (const n of graph.nodes) {
    if (!parents.get(n.id)?.length) {
      layer.set(n.id, 0)
      queue.push(n.id)
    }
  }
  while (queue.length) {
    const id = queue.shift() as string
    for (const c of children.get(id) ?? []) {
      if (!layer.has(c)) {
        layer.set(c, (layer.get(id) ?? 0) + 1)
        queue.push(c)
      }
    }
  }
  const byLayer = new Map<number, GraphNode[]>()
  for (const n of graph.nodes) {
    const l = layer.get(n.id) ?? n.depth ?? 0
    byLayer.set(l, [...(byLayer.get(l) ?? []), n])
  }
  const nodes: LaidOutNode[] = []
  let rows = 0
  for (const [l, list] of [...byLayer.entries()].sort((a, b) => a[0] - b[0])) {
    list.sort((a, b) => a.name.localeCompare(b.name))
    list.forEach((n, row) => nodes.push({ ...n, layer: l, row }))
    rows = Math.max(rows, list.length)
  }
  const layers = byLayer.size ? Math.max(...byLayer.keys()) + 1 : 0
  return { nodes, layers, rows }
}

/** Nodes with open vulnerabilities and every node on a path to one. */
export function vulnerablePaths(graph: Graph): Set<string> {
  const parents = new Map<string, string[]>()
  for (const e of graph.edges) parents.set(e.to, [...(parents.get(e.to) ?? []), e.from])
  const out = new Set<string>()
  const stack = graph.nodes.filter((n) => worstSeverity(n)).map((n) => n.id)
  while (stack.length) {
    const id = stack.pop() as string
    if (out.has(id)) continue
    out.add(id)
    stack.push(...(parents.get(id) ?? []))
  }
  return out
}

type View = 'graph' | 'list'

export function DependencyGraphView({
  graph,
  focusVersionId,
}: {
  graph: Graph
  focusVersionId?: string | null
}) {
  const { t } = useTranslation()
  const router = useRouter()
  const [query, setQuery] = useState('')
  const [view, setView] = useState<View>('graph')
  useEffect(() => {
    if (typeof window !== 'undefined' && window.matchMedia?.('(max-width: 767px)').matches)
      setView('list')
  }, [])

  const { nodes, layers, rows } = useMemo(() => layoutGraph(graph), [graph])
  const hot = useMemo(() => vulnerablePaths(graph), [graph])
  const pos = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes])
  const q = query.trim().toLowerCase()
  const matches = (n: GraphNode) =>
    q !== '' && (n.name.toLowerCase().includes(q) || n.purl.toLowerCase().includes(q))

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="relative w-full sm:w-64">
          <Search
            className="pointer-events-none absolute start-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('components.graph.search', 'Find a package…')}
            aria-label={t('components.graph.searchLabel', 'Find a package in the graph')}
            className="h-9 ps-8"
          />
        </div>
        <SegmentedLens<View>
          label={t('components.graph.view', 'Graph view')}
          value={view}
          onChange={setView}
          options={[
            { value: 'graph', label: t('components.graph.graph', 'Graph') },
            { value: 'list', label: t('components.graph.list', 'List') },
          ]}
        />
      </div>
      <p className="text-xs text-muted-foreground">
        {t(
          'components.graph.legend',
          '{nodes} packages, {edges} dependency links. Highlighted: packages with open vulnerabilities and the paths that bring them in.',
          {
            nodes: graph.nodes.length,
            edges: graph.edges.length,
          }
        )}
        {graph.truncated &&
          ` ${t('components.graph.truncated', 'Only part of the graph is shown (500 packages, 10 levels at most).')}`}
      </p>

      {view === 'graph' ? (
        <div className="overflow-auto rounded-md border bg-card" style={{ maxHeight: '60vh' }}>
          <svg
            width={Math.max(layers * COL_W, COL_W)}
            height={Math.max(rows * ROW_H + 16, ROW_H)}
            role="group"
            aria-label={t('components.graph.label', 'Dependency graph')}
          >
            {graph.edges.map((e) => {
              const a = pos.get(e.from)
              const b = pos.get(e.to)
              if (!a || !b) return null
              const x1 = a.layer * COL_W + 8 + NODE_W
              const y1 = a.row * ROW_H + 8 + NODE_H / 2
              const x2 = b.layer * COL_W + 8
              const y2 = b.row * ROW_H + 8 + NODE_H / 2
              const mid = (x1 + x2) / 2
              const lit = hot.has(e.from) && hot.has(e.to)
              return (
                <path
                  key={`${e.from}-${e.to}`}
                  d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`}
                  fill="none"
                  className={cn(lit ? 'stroke-destructive' : 'stroke-border')}
                  strokeWidth={lit ? 1.75 : 1}
                />
              )
            })}
            {nodes.map((n) => {
              const sev = worstSeverity(n)
              const focus = focusVersionId && n.version_id === focusVersionId
              return (
                <g
                  key={n.id}
                  role="link"
                  tabIndex={0}
                  aria-label={`${n.name} ${n.version}`}
                  onClick={() => router.push(`/components/${n.component_id}`)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      router.push(`/components/${n.component_id}`)
                    }
                  }}
                  transform={`translate(${n.layer * COL_W + 8},${n.row * ROW_H + 8})`}
                  className="cursor-pointer outline-none focus-visible:[&>rect]:stroke-primary"
                >
                  <rect
                    width={NODE_W}
                    height={NODE_H}
                    rx={6}
                    className={cn(
                      'fill-background stroke-border',
                      hot.has(n.id) && 'stroke-destructive/60',
                      (focus || matches(n)) && 'stroke-primary',
                      q !== '' && !matches(n) && 'opacity-40'
                    )}
                    strokeWidth={focus || matches(n) ? 2.5 : 1}
                  />
                  {sev && (
                    <circle cx={12} cy={NODE_H / 2} r={4} fill={SEVERITY_CHART_COLORS[sev]} />
                  )}
                  <text
                    x={sev ? 22 : 10}
                    y={NODE_H / 2 + 4}
                    className="fill-foreground text-[11px]"
                  >
                    {`${n.name}@${n.version}`.slice(0, 26)}
                  </text>
                  <title>{`${n.purl}${n.kev ? ' (KEV)' : ''}`}</title>
                </g>
              )
            })}
          </svg>
        </div>
      ) : (
        <GraphList graph={graph} hot={hot} query={q} focusVersionId={focusVersionId} />
      )}
    </div>
  )
}

/** The graph as an indented tree (a node seen before is not expanded again). */
function GraphList({
  graph,
  hot,
  query,
  focusVersionId,
}: {
  graph: Graph
  hot: Set<string>
  query: string
  focusVersionId?: string | null
}) {
  const children = useMemo(() => {
    const m = new Map<string, string[]>()
    for (const e of graph.edges) m.set(e.from, [...(m.get(e.from) ?? []), e.to])
    return m
  }, [graph])
  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph])
  const roots = useMemo(() => {
    const hasParent = new Set(graph.edges.map((e) => e.to))
    return graph.nodes.filter((n) => !hasParent.has(n.id))
  }, [graph])

  const rows: { node: GraphNode; level: number; repeat: boolean }[] = []
  const seen = new Set<string>()
  const walk = (id: string, level: number) => {
    const node = byId.get(id)
    if (!node || rows.length > 2000) return
    const repeat = seen.has(id)
    rows.push({ node, level, repeat })
    if (repeat) return
    seen.add(id)
    for (const c of children.get(id) ?? []) walk(c, level + 1)
  }
  for (const r of roots.length ? roots : graph.nodes) walk(r.id, 0)

  return (
    <ul className="max-h-[60vh] overflow-auto rounded-md border text-sm">
      {rows.map(({ node, level, repeat }, i) => {
        const sev = worstSeverity(node)
        const lit =
          query !== '' &&
          (node.name.toLowerCase().includes(query) || node.purl.toLowerCase().includes(query))
        return (
          <li
            key={`${node.id}-${i}`}
            className={cn(
              'flex items-center gap-2 border-b py-1.5 pe-3 last:border-b-0',
              hot.has(node.id) && 'bg-destructive/5',
              (lit || node.version_id === focusVersionId) && 'bg-primary/10'
            )}
            style={{ paddingInlineStart: `${12 + level * 16}px` }}
          >
            {sev ? (
              <span
                aria-hidden
                className={cn('h-2 w-2 shrink-0 rounded-full', SEVERITY_DOT_COLORS[sev])}
              />
            ) : (
              <span aria-hidden className="h-2 w-2 shrink-0" />
            )}
            <Link
              href={`/components/${node.component_id}`}
              className={cn('min-w-0 truncate hover:underline', repeat && 'text-muted-foreground')}
            >
              {node.name}
              <span className="ms-1 font-mono text-xs text-muted-foreground">{node.version}</span>
            </Link>
          </li>
        )
      })}
    </ul>
  )
}
