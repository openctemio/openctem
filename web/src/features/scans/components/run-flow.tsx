'use client'

import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  AlertTriangle,
  ArrowDown,
  CheckCircle2,
  Circle,
  GitBranch,
  Hourglass,
  ListOrdered,
  Loader2,
  MinusCircle,
  ShieldAlert,
  XCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import type { RunMap, RunMapNode } from '@/lib/api/generated'
import { cn } from '@/lib/utils'
import {
  compactCount,
  egressRefusedText,
  guardRefusedText,
  mapStateLabel,
  outputsDeltaLabel,
  stepEgressRefused,
  stepGuardRefused,
  type EgressCountedTask,
} from '../lib/run-map'
import {
  FLOW_CARD_WIDTH,
  FLOW_GAP_X,
  FLOW_GAP_Y,
  FLOW_SIBLING_GAP,
  edgeHandOff,
  flowDirection,
  flowLayers,
  flowTone,
  skippedReasonText,
  stepDurationLabel,
  stepProgress,
  hasParallelBranches,
  type FlowTone,
} from '../lib/run-flow'

const TONE: Record<
  FlowTone,
  { card: string; icon: string; badge: string; bar: string; edge: string; Icon: typeof Circle }
> = {
  pending: {
    card: '',
    icon: 'text-muted-foreground',
    badge: 'bg-muted text-muted-foreground',
    bar: 'bg-muted-foreground/40',
    edge: 'text-muted-foreground/50',
    Icon: Circle,
  },
  waiting: {
    card: '',
    icon: 'text-warning',
    badge: 'bg-warning/10 text-warning',
    bar: 'bg-warning',
    edge: 'text-muted-foreground/50',
    Icon: Hourglass,
  },
  running: {
    card: '',
    icon: 'text-info motion-safe:animate-spin',
    badge: 'bg-info/10 text-info',
    bar: 'bg-info',
    edge: 'text-info',
    Icon: Loader2,
  },
  done: {
    card: '',
    icon: 'text-success',
    badge: 'bg-success/10 text-success',
    bar: 'bg-success',
    edge: 'text-success/70',
    Icon: CheckCircle2,
  },
  partial: {
    card: '',
    icon: 'text-warning',
    badge: 'bg-warning/10 text-warning',
    bar: 'bg-warning',
    edge: 'text-warning/70',
    Icon: AlertTriangle,
  },
  failed: {
    card: '',
    icon: 'text-destructive',
    badge: 'bg-destructive/10 text-destructive',
    bar: 'bg-destructive',
    edge: 'text-destructive/60',
    Icon: XCircle,
  },
  skipped: {
    card: 'opacity-80',
    icon: 'text-muted-foreground',
    badge: 'bg-muted text-muted-foreground',
    bar: 'bg-muted-foreground/40',
    edge: 'text-muted-foreground/40',
    Icon: MinusCircle,
  },
}

/** The width of an element, kept current (0 until measured). */
function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T | null>(null)
  const [width, setWidth] = useState(0)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    setWidth(el.clientWidth)
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => setWidth(el.clientWidth))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, width]
}

/** Now, ticking once a second while some step runs (durations stay live). */
function useNow(live: boolean): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!live) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [live])
  return now
}

/**
 * A run's steps as one flow: each step a card with its state (colour,
 * icon, badge), tool, chunk progress, outputs, findings, duration, how it
 * compares with the last run and why it failed or did not run. Steps that
 * run side by side are drawn as a graph (left to right, or top to bottom
 * when that is what fits) with each dependency an arrow labelled with what
 * flowed along it; a chain, and any screen too narrow for the graph, gets
 * the list. Every card is a button that opens the step.
 */
export function RunFlow({
  map,
  tasks,
  selected,
  onSelect,
}: {
  map: RunMap
  tasks?: EgressCountedTask[]
  selected: string | null
  onSelect: (stepKey: string) => void
}) {
  const { t } = useTranslation()
  const nodes = useMemo(() => map.nodes ?? [], [map])
  const byKey = useMemo(() => new Map(nodes.map((n) => [n.step_key ?? '', n])), [nodes])
  const layers = useMemo(() => flowLayers(nodes), [nodes])
  const parallel = hasParallelBranches(layers)
  const [boxRef, width] = useWidth<HTMLDivElement>()
  const direction = flowDirection(layers, width)
  const [choice, setChoice] = useState<'graph' | 'list'>('graph')
  const view = direction && choice === 'graph' ? 'graph' : 'list'
  const now = useNow(nodes.some((n) => n.state === 'running'))

  const card = (n: RunMapNode, fixed: boolean) => (
    <StepCard
      key={n.step_key}
      node={n}
      byKey={byKey}
      egress={stepEgressRefused(tasks, n.step_key ?? '')}
      guard={stepGuardRefused(tasks, n.step_key ?? '')}
      now={now}
      selected={selected === n.step_key}
      fixedWidth={fixed}
      onSelect={() => onSelect(n.step_key ?? '')}
    />
  )

  return (
    <div ref={boxRef} className="space-y-2" role="region" aria-label={t('scans.flow.label')}>
      {parallel && direction ? (
        <div className="flex justify-end">
          <div role="group" aria-label={t('scans.flow.view')} className="flex">
            <Button
              type="button"
              size="sm"
              variant={view === 'graph' ? 'secondary' : 'ghost'}
              className="h-7 px-2 text-xs"
              aria-pressed={view === 'graph'}
              onClick={() => setChoice('graph')}
            >
              <GitBranch className="me-1 h-3.5 w-3.5" />
              {t('scans.flow.viewGraph')}
            </Button>
            <Button
              type="button"
              size="sm"
              variant={view === 'list' ? 'secondary' : 'ghost'}
              className="h-7 px-2 text-xs"
              aria-pressed={view === 'list'}
              onClick={() => setChoice('list')}
            >
              <ListOrdered className="me-1 h-3.5 w-3.5" />
              {t('scans.flow.viewList')}
            </Button>
          </div>
        </div>
      ) : null}
      {view === 'graph' && direction ? (
        <FlowGraph map={map} layers={layers} byKey={byKey} direction={direction}>
          {(n) => card(n, true)}
        </FlowGraph>
      ) : (
        <FlowList map={map} layers={layers} byKey={byKey}>
          {(n) => card(n, false)}
        </FlowList>
      )}
    </div>
  )
}

/** The steps in dependency order, one per row, each joined to the one before. */
function FlowList({
  map,
  layers,
  byKey,
  children,
}: {
  map: RunMap
  layers: string[][]
  byKey: Map<string, RunMapNode>
  children: (n: RunMapNode) => ReactNode
}) {
  const { t } = useTranslation()
  const order = layers.flat()
  return (
    <ol className="space-y-1">
      {order.map((key, i) => {
        const n = byKey.get(key)
        if (!n) return null
        const deps = (n.depends_on ?? []).filter((d) => byKey.has(d))
        const name = n.name || key
        const nameOf = (k: string) => byKey.get(k)?.name || k
        let link: string | null = null
        if (deps.length === 1 && deps[0] === order[i - 1]) {
          const what = edgeHandOff(map, deps[0], key, t)
          link = what ? t('scans.flow.handOff', undefined, { what, step: name }) : ''
        } else if (deps.length > 0) {
          link = t('scans.flow.waitsFor', undefined, { steps: deps.map(nameOf).join(', ') })
        }
        return (
          <li key={key}>
            {link !== null ? (
              <p className="flex items-center gap-1.5 py-1 ps-3 text-xs text-muted-foreground">
                <ArrowDown className="h-3.5 w-3.5 shrink-0" aria-hidden />
                {link}
              </p>
            ) : null}
            {children(n)}
          </li>
        )
      })}
    </ol>
  )
}

type EdgePath = {
  id: string
  from: string
  d: string
  tone: FlowTone
  label?: string
  lx: number
  ly: number
}

/**
 * The graph: one column (or row) per layer, laid out by CSS so cards never
 * overlap or clip, and the dependencies drawn over it as arrows measured
 * from the cards themselves.
 */
function FlowGraph({
  map,
  layers,
  byKey,
  direction,
  children,
}: {
  map: RunMap
  layers: string[][]
  byKey: Map<string, RunMapNode>
  direction: 'LR' | 'TB'
  children: (n: RunMapNode) => ReactNode
}) {
  const { t } = useTranslation()
  const box = useRef<HTMLDivElement | null>(null)
  const [paths, setPaths] = useState<EdgePath[]>([])
  const [size, setSize] = useState({ w: 0, h: 0 })
  const drawn = useRef('')
  const lr = direction === 'LR'

  useLayoutEffect(() => {
    const el = box.current
    if (!el) return
    const measure = () => {
      const origin = el.getBoundingClientRect()
      const cards = new Map<string, HTMLElement>()
      el.querySelectorAll<HTMLElement>('[data-step]').forEach((c) => {
        cards.set(c.dataset.step ?? '', c)
      })
      const rectOf = (k: string) => {
        const c = cards.get(k)?.firstElementChild
        if (!c) return null
        const r = c.getBoundingClientRect()
        return { x: r.left - origin.left, y: r.top - origin.top, w: r.width, h: r.height }
      }
      const out: EdgePath[] = []
      for (const n of byKey.values()) {
        const to = n.step_key ?? ''
        const b = rectOf(to)
        if (!b) continue
        for (const from of n.depends_on ?? []) {
          const a = rectOf(from)
          if (!a) continue
          const [x1, y1, x2, y2] = lr
            ? [a.x + a.w, a.y + a.h / 2, b.x, b.y + b.h / 2]
            : [a.x + a.w / 2, a.y + a.h, b.x + b.w / 2, b.y]
          const d = lr
            ? `M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2 - 2},${y2}`
            : `M${x1},${y1} C${x1},${(y1 + y2) / 2} ${x2},${(y1 + y2) / 2} ${x2},${y2 - 2}`
          out.push({
            id: `${from}->${to}`,
            from,
            d,
            tone: flowTone(byKey.get(from)?.state),
            label: edgeHandOff(map, from, to, t) ?? undefined,
            lx: (x1 + x2) / 2,
            ly: (y1 + y2) / 2,
          })
        }
      }
      // A step that hands the same to several steps gets one label, on the
      // shared stem by the step, not one per branch.
      const bySource = new Map<string, EdgePath[]>()
      for (const p of out) bySource.set(p.from, [...(bySource.get(p.from) ?? []), p])
      for (const group of bySource.values()) {
        if (group.length < 2 || !group[0].label || group.some((p) => p.label !== group[0].label))
          continue
        const a = rectOf(group[0].from)!
        group.forEach((p, i) => {
          if (i > 0) p.label = undefined
        })
        group[0].lx = lr ? a.x + a.w + FLOW_GAP_X / 2 : a.x + a.w / 2
        group[0].ly = lr ? a.y + a.h / 2 : a.y + a.h + FLOW_GAP_Y / 3
      }
      // Only a real change re-renders (a resize, a step that changed).
      const next = JSON.stringify(out)
      if (next !== drawn.current) {
        drawn.current = next
        setPaths(out)
      }
      const w = el.scrollWidth
      const h = el.scrollHeight
      setSize((cur) => (cur.w === w && cur.h === h ? cur : { w, h }))
    }
    measure()
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [map, byKey, lr, t])

  return (
    <div className="overflow-x-auto py-1">
      <div ref={box} className="relative mx-auto w-fit">
        <svg
          aria-hidden
          className="pointer-events-none absolute inset-0 overflow-visible"
          width={size.w}
          height={size.h}
        >
          <defs>
            {(Object.keys(TONE) as FlowTone[]).map((tone) => (
              <marker
                key={tone}
                id={`run-flow-arrow-${tone}`}
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
                className={TONE[tone].edge}
              >
                <path d="M0,0 L10,5 L0,10 z" fill="currentColor" />
              </marker>
            ))}
          </defs>
          {paths.map((p) => (
            <path
              key={p.id}
              d={p.d}
              fill="none"
              stroke="currentColor"
              strokeWidth={1.5}
              strokeDasharray={p.tone === 'pending' || p.tone === 'skipped' ? '4 4' : undefined}
              markerEnd={`url(#run-flow-arrow-${p.tone})`}
              className={TONE[p.tone].edge}
            />
          ))}
        </svg>
        {paths
          .filter((p) => p.label)
          .map((p) => (
            <span
              key={p.id}
              aria-hidden
              className="pointer-events-none absolute -translate-x-1/2 -translate-y-1/2 rounded-full border bg-background px-1.5 py-px text-meta whitespace-nowrap text-muted-foreground tabular-nums"
              style={{ left: p.lx, top: p.ly }}
            >
              {p.label}
            </span>
          ))}
        <ol
          className={cn('relative flex', lr ? 'flex-row items-center' : 'flex-col items-center')}
          style={{ gap: lr ? FLOW_GAP_X : FLOW_GAP_Y }}
        >
          {layers.map((layer, i) => (
            <li key={i}>
              <ul
                className={cn(
                  'flex',
                  lr ? 'flex-col justify-center' : 'flex-row items-start justify-center'
                )}
                style={{ gap: FLOW_SIBLING_GAP }}
              >
                {layer.map((k) => {
                  const n = byKey.get(k)
                  return n ? (
                    <li key={k} data-step={k}>
                      {children(n)}
                    </li>
                  ) : null
                })}
              </ul>
            </li>
          ))}
        </ol>
      </div>
    </div>
  )
}

function StepCard({
  node,
  byKey,
  egress,
  guard,
  now,
  selected,
  fixedWidth,
  onSelect,
}: {
  node: RunMapNode
  byKey: Map<string, RunMapNode>
  egress: number
  guard: number
  now: number
  selected: boolean
  fixedWidth: boolean
  onSelect: () => void
}) {
  const { t } = useTranslation()
  const blocked = egressRefusedText(node, egress, t)
  const guarded = guardRefusedText(node, guard, t)
  // A finished step whose targets the sensor's egress or target guard
  // refused is not a clean "done": it is drawn as a warning (its state
  // label stays).
  const warned = blocked || guarded
  const tone = warned && flowTone(node.state) === 'done' ? 'partial' : flowTone(node.state)
  const style = warned ? { ...TONE[tone], Icon: ShieldAlert } : TONE[tone]
  const name = node.name || node.step_key || ''
  const state = mapStateLabel(node.state ?? 'pending', t)
  const progress = stepProgress(node)
  const total = node.chunks?.total ?? 0
  const failedChunks = node.chunks?.failed ?? 0
  const done = (node.chunks?.completed ?? 0) + failedChunks
  const duration = stepDurationLabel(node, now)
  const outputs = node.outputs?.total ?? 0
  const findings = node.findings ?? 0
  const delta = outputsDeltaLabel(node, t)
  const skipped = skippedReasonText(node, byKey, t)
  const failure =
    (tone === 'failed' || tone === 'partial' || tone === 'skipped') && !skipped && node.reason
      ? node.reason.toLowerCase().replace(/_/g, ' ')
      : null
  const counts: string[] = []
  if (outputs > 0) counts.push(t('scans.map.outputs', undefined, { count: compactCount(outputs) }))
  if (findings > 0)
    counts.push(t('scans.map.findings', undefined, { count: compactCount(findings) }))

  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      aria-label={t('scans.flow.open', undefined, { name, state })}
      className={cn(
        'block rounded-md border bg-card p-2.5 text-start text-xs shadow-xs transition-colors hover:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
        style.card,
        selected && 'ring-2 ring-primary',
        fixedWidth ? 'w-[var(--card-w)]' : 'w-full'
      )}
      style={
        fixedWidth ? ({ '--card-w': `${FLOW_CARD_WIDTH}px` } as React.CSSProperties) : undefined
      }
    >
      <span className="flex items-start gap-2">
        <style.Icon className={cn('mt-0.5 h-4 w-4 shrink-0', style.icon)} aria-hidden />
        <span className="min-w-0 flex-1 text-sm leading-snug font-medium [overflow-wrap:anywhere]">
          {name}
        </span>
      </span>
      <span className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-muted-foreground">
        <span className={cn('rounded px-1.5 py-px text-meta font-medium', style.badge)}>
          {state}
        </span>
        {node.tool ? <span className="font-mono">{node.tool}</span> : null}
        {duration ? (
          <span className="whitespace-nowrap tabular-nums">
            {node.completed_at
              ? t('scans.flow.took', undefined, { duration })
              : t('scans.flow.runningFor', undefined, { duration })}
          </span>
        ) : null}
      </span>
      {progress !== null ? (
        <span className="mt-2 block">
          <span
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progress}
            aria-valuetext={t('scans.flow.progress', undefined, { percent: progress })}
            className="block h-1.5 overflow-hidden rounded-full bg-muted"
          >
            <span className={cn('block h-full', style.bar)} style={{ width: `${progress}%` }} />
          </span>
          <span className="mt-1 block text-muted-foreground tabular-nums">
            {t('scans.map.chunks', undefined, { done, total })}
            {failedChunks ? t('scans.map.chunksFailed', undefined, { count: failedChunks }) : ''}
          </span>
        </span>
      ) : null}
      {counts.length > 0 ? <span className="mt-1 block">{counts.join(', ')}</span> : null}
      {delta ? <span className="mt-0.5 block text-muted-foreground">{delta}</span> : null}
      {blocked ? (
        <span className="mt-1 flex items-start gap-1 text-warning">
          <ShieldAlert className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
          {blocked}
        </span>
      ) : null}
      {guarded ? (
        <span className="mt-1 flex items-start gap-1 text-warning">
          <ShieldAlert className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
          {guarded}
        </span>
      ) : null}
      {skipped ? <span className="mt-1 block text-muted-foreground">{skipped}</span> : null}
      {failure ? <span className="mt-1 block text-destructive">{failure}</span> : null}
    </button>
  )
}
