'use client'

/**
 * The exposure flow (metric exposure.flow; api docs/architecture/dashboards.md,
 * "Exposure flow and intake"): sources on the left, the CTEM core in the
 * middle (received to actionable, a labelled ring of actionable findings by
 * priority class, the five stages), outcomes on the right. Every figure is a
 * link to the list it counts; the ring is the part-to-whole of the number in
 * its centre, at most four arcs, each labelled with its value and focusable.
 *
 * Hover, keyboard focus or a first tap lights an element and its path, dims
 * the rest and opens a tooltip (definition, figures, the list). Below the
 * large breakpoint the columns stack and the wires are dropped; every number
 * stays a link. "Show table" gives the same figures as tables.
 */

import { useMemo, useRef } from 'react'
import { useRouter } from 'next/navigation'
import { Check, Minus, TriangleAlert, X } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { formatCount, formatMetric, formatRelativeTime } from '@/lib/format-metric'
import { PRIORITY_CHART_COLORS, isPriorityClass } from '@/lib/priority-colors'
import { SEVERITY_CHART_COLORS } from '@/lib/severity-colors'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import {
  FlowLink,
  FlowTip,
  tCount,
  dimClass,
  useFlowFocus,
  useWireAnchors,
  wirePath,
  wireStroke,
  wireWidth,
  type FlowTipContent,
} from './flow-parts'
import { ChartOrTable, usePrefersReducedMotion } from './viz-parts'
import type { FlowFigure, FlowResult, IntakeSourceRow, Stage, StageState } from './types'

/** The most source rows the hero lists; the rest are one link to every receipt. */
const MAX_SOURCES = 6

type Translate = ReturnType<typeof useTranslation>['t']

/** The words of a source group. */
export function originLabel(t: Translate, origin: string): string {
  switch (origin) {
    case 'sensor':
      return t('dashboardKit.flow.origin.sensor', 'Sensor')
    case 'import':
      return t('dashboardKit.flow.origin.import', 'Import')
    case 'connector':
      return t('dashboardKit.flow.origin.connector', 'Connector')
    case 'ci':
      return t('dashboardKit.flow.origin.ci', 'CI')
    default:
      return origin
  }
}

/** The name of a source: its tool, or "Unnamed tool". */
export function sourceName(t: Translate, s: IntakeSourceRow): string {
  return s.tool === 'unknown' || !s.tool
    ? t('dashboardKit.flow.unnamedTool', 'Unnamed tool')
    : toDisplayText(s.tool, 80)
}

/** "Stale, last 3 days ago" / "Failed 2 hours ago", or null when healthy. */
export function healthNote(t: Translate, s: IntakeSourceRow, locale: string): string | null {
  if (s.health === 'ok') return null
  const when = formatRelativeTime(s.last_at, locale)
  return s.health === 'failed'
    ? t('dashboardKit.flow.health.failed', 'Failed {when}', { when })
    : t('dashboardKit.flow.health.stale', 'Stale, last {when}', { when })
}

const STAGE_GLYPH: Record<StageState, React.ReactNode> = {
  good: <Check className="size-3" aria-hidden />,
  warn: <TriangleAlert className="size-3" aria-hidden />,
  crit: <X className="size-3" aria-hidden />,
  unmeasured: <Minus className="size-3" aria-hidden />,
}

interface Arc {
  key: string
  value: number
  d: string
  labelX: number
  labelY: number
  color: string
}

const R = 112
const GAP = 0.035
const MIN_SWEEP = 0.09

function arcPath(a0: number, a1: number): string {
  const p = (a: number) => [R * Math.sin(a), -R * Math.cos(a)]
  const [sx, sy] = p(a0)
  const [ex, ey] = p(a1)
  return `M${sx.toFixed(2)} ${sy.toFixed(2)} A${R} ${R} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${ex.toFixed(2)} ${ey.toFixed(2)}`
}

/**
 * The arcs of the ring: one per class with findings, in fixed order, each at
 * least MIN_SWEEP so a small P0 stays visible, the largest centred at the
 * bottom, away from the wire joints at 9 and 3 o'clock.
 */
export function ringArcs(classes: FlowFigure[]): Arc[] {
  const parts = classes.filter((c) => c.value > 0)
  const total = parts.reduce((s, c) => s + c.value, 0)
  if (total === 0) return []
  const n = parts.length
  const gap = n > 1 ? GAP : 0
  const spare = 2 * Math.PI - n * (MIN_SWEEP + gap)
  const sweeps = parts.map((c) => MIN_SWEEP + (spare * c.value) / total)
  let big = 0
  parts.forEach((c, i) => {
    if (c.value > parts[big].value) big = i
  })
  let before = 0
  for (let i = 0; i < big; i++) before += sweeps[i] + gap
  let a = Math.PI - (before + sweeps[big] / 2)
  return parts.map((c, i) => {
    const a0 = a
    const a1 = a + sweeps[i]
    a = a1 + gap
    const mid = (a0 + a1) / 2
    const lr = R + 26
    return {
      key: c.key ?? '',
      value: c.value,
      d: n === 1 ? `M0 ${-R} A${R} ${R} 0 1 1 -0.01 ${-R}` : arcPath(a0, a1),
      labelX: lr * Math.sin(mid),
      labelY: -lr * Math.cos(mid),
      color: isPriorityClass(c.key) ? PRIORITY_CHART_COLORS[c.key] : 'var(--muted-foreground)',
    }
  })
}

export function ExposureFlowViz({
  result,
  scope,
}: {
  result: FlowResult
  /** Whose numbers these are (the dashboard's read). */
  scope?: 'organization' | 'personal'
}) {
  const { t, locale } = useTranslation()
  const n = (v: number) => formatCount(v, locale)
  const counts = { actionable: n(result.actionable.value), open: n(result.open.value) }
  const summary = result.intake
    ? t(
        'dashboardKit.flow.summary',
        'Exposure flow: {received} received, {actionable} actionable, {open} open.',
        { ...counts, received: n(result.intake.totals.received) }
      )
    : t(
        'dashboardKit.flow.summaryScoped',
        'Exposure flow: {actionable} actionable, {open} open.',
        counts
      )
  return (
    <ChartOrTable
      chart={<FlowChart result={result} scope={scope} />}
      table={<FlowTable result={result} />}
      summary={summary}
      lead={
        <span className="flex flex-wrap gap-1.5 text-xs text-muted-foreground">
          <span className="rounded border px-1.5 py-0.5 tabular-nums">
            {t('dashboardKit.flow.period', '{days} days', { days: result.days })}
          </span>
          <span className="rounded border px-1.5 py-0.5">
            {scope === 'organization'
              ? t('dashboardKit.flow.scopeOrgChip', 'Organization')
              : t('dashboardKit.flow.scopeMineChip', 'Your scope')}
          </span>
        </span>
      }
    />
  )
}

function FlowChart({ result, scope }: { result: FlowResult; scope?: 'organization' | 'personal' }) {
  const { t, locale } = useTranslation()
  const n = (v: number) => formatCount(v, locale)
  const ref = useRef<HTMLDivElement>(null)
  const router = useRouter()
  const reduced = usePrefersReducedMotion()
  const { active, anchor, tipId, bind, containerProps } = useFlowFocus(ref)
  const intake = result.intake
  const sources = intake?.sources ?? []
  const shown = sources.slice(0, MAX_SOURCES)
  const more = sources.length - shown.length
  const arcs = useMemo(() => ringArcs(result.classes), [result.classes])
  const actionableTotal = result.actionable.value

  const outcomes: Array<{
    key: string
    label: string
    fig: FlowFigure
    sub?: boolean
    tone?: 'bad'
  }> = [
    { key: 'open', label: t('dashboardKit.flow.outcome.open', 'Open'), fig: result.open },
    {
      key: 'past_sla',
      label: t('dashboardKit.flow.outcome.pastSla', 'Past SLA'),
      fig: result.past_sla,
      sub: true,
      tone: 'bad',
    },
    {
      key: 'in_progress',
      label: t('dashboardKit.flow.outcome.inProgress', 'In progress'),
      fig: result.in_progress,
    },
    { key: 'fixed', label: t('dashboardKit.flow.outcome.fixed', 'Fixed'), fig: result.fixed },
    {
      key: 'accepted',
      label: t('dashboardKit.flow.outcome.accepted', 'Accepted'),
      fig: result.accepted,
    },
    {
      key: 'false_positive',
      label: t('dashboardKit.flow.outcome.falsePositive', 'False positive'),
      fig: result.false_positive,
    },
  ]

  const layout = useWireAnchors(ref, [shown.length, result.open.value])
  const maxSource = Math.max(1, ...shown.map((s) => s.received))
  const maxOutcome = Math.max(1, ...outcomes.map((o) => o.fig.value))

  // What lights with what: a source lights its wire, the funnel and the
  // ring; a class its arc and the ring; an outcome its wire and the ring.
  const lit = (k: string): boolean => {
    if (!active) return false
    if (k === active) return true
    if (k === 'ring') return /^(s|p|o|f):/.test(active)
    if (k === 'funnel') return active.startsWith('s:') || active.startsWith('f:')
    if (k.startsWith('w:')) return k.slice(2) === active
    return false
  }

  const classLabel = (key: string) => key
  const activeClass = active?.startsWith('p:')
    ? result.classes.find((c) => `p:${c.key}` === active)
    : undefined

  const tip = ((): FlowTipContent | null => {
    if (!active) return null
    if (active.startsWith('s:')) {
      const s = sources.find((x) => `s:${x.id}` === active)
      if (!s) return null
      return {
        title: t('dashboardKit.flow.tip.sourceTitle', '{name}: received', {
          name: sourceName(t, s),
        }),
        rows: [
          [t('dashboardKit.flow.tip.received', 'Received'), n(s.received)],
          [
            t('dashboardKit.flow.tip.newOrReopened', 'New or reopened'),
            n(Math.max(0, s.created - s.suppressed) + s.reopened),
          ],
          [t('dashboardKit.flow.tip.receipts', 'Receipts'), n(s.receipts)],
          [
            t('dashboardKit.flow.tip.lastReceipt', 'Last receipt'),
            formatRelativeTime(s.last_at, locale),
          ],
        ],
        definition: t(
          'dashboardKit.flow.tip.sourceDef',
          'Findings this source reported in the period, from its import and run receipts. An organization figure.'
        ),
        link: {
          label: tCount(
            t,
            'dashboardKit.flow.tip.viewReceipts',
            'View {count} receipts',
            'View {count} receipt',
            s.receipts,
            { count: n(s.receipts) }
          ),
          href: s.drill,
        },
      }
    }
    if (active.startsWith('p:')) {
      const c = activeClass
      if (!c) return null
      const share = actionableTotal > 0 ? Math.round((100 * c.value) / actionableTotal) : 0
      return {
        title: t('dashboardKit.flow.tip.classTitle', 'Actionable: {class}', { class: c.key ?? '' }),
        rows: [
          [t('dashboardKit.flow.tip.findings', 'Findings'), n(c.value)],
          [t('dashboardKit.flow.tip.share', 'Share of actionable'), `${share}%`],
        ],
        definition: t(
          `dashboardKit.flow.classDef.${c.key}`,
          'Open findings in this priority class, counted now.'
        ),
        link: {
          label: tCount(
            t,
            'dashboardKit.flow.tip.viewFindings',
            'View {count} findings',
            'View {count} finding',
            c.value,
            { count: n(c.value) }
          ),
          href: c.drill,
        },
      }
    }
    if (active.startsWith('o:')) {
      const o = outcomes.find((x) => `o:${x.key}` === active)
      if (!o) return null
      const rows: Array<[string, string]> =
        o.key === 'open'
          ? result.severity.map((r) => [t(`severity.${r.key}`, r.key ?? ''), n(r.value)])
          : [[t('dashboardKit.flow.tip.findings', 'Findings'), n(o.fig.value)]]
      return {
        title: o.label,
        rows,
        definition: t(`dashboardKit.flow.outcomeDef.${o.key}`, ''),
        link: {
          label: tCount(
            t,
            'dashboardKit.flow.tip.viewFindings',
            'View {count} findings',
            'View {count} finding',
            o.fig.value,
            { count: n(o.fig.value) }
          ),
          href: o.fig.drill,
        },
      }
    }
    if (active.startsWith('f:') && intake) {
      const which = active.slice(2)
      const fig =
        which === 'received'
          ? {
              v: intake.totals.received,
              href: intake.drill,
              def: t('dashboardKit.flow.funnelDef.received', ''),
            }
          : which === 'new'
            ? {
                v: intake.noise.new,
                href: intake.drill,
                def: t('dashboardKit.flow.funnelDef.new', ''),
              }
            : {
                v: result.actionable.value,
                href: result.actionable.drill,
                def: t('dashboardKit.flow.funnelDef.actionable', ''),
              }
      return {
        title: t(`dashboardKit.flow.funnel.${which}`, which),
        rows: [[t('dashboardKit.flow.tip.findings', 'Findings'), n(fig.v)]],
        definition: fig.def,
        link: {
          label:
            which === 'actionable'
              ? tCount(
                  t,
                  'dashboardKit.flow.tip.viewFindings',
                  'View {count} findings',
                  'View {count} finding',
                  fig.v,
                  { count: n(fig.v) }
                )
              : tCount(
                  t,
                  'dashboardKit.flow.tip.viewReceipts',
                  'View {count} receipts',
                  'View {count} receipt',
                  intake.totals.receipts,
                  { count: n(intake.totals.receipts) }
                ),
          href: fig.href,
        },
      }
    }
    return null
  })()

  const centreValue = activeClass ? activeClass.value : actionableTotal
  const periodLabel = t('dashboardKit.flow.period', '{days} days', { days: result.days })

  return (
    <div className="flex flex-col gap-4">
      <div
        ref={ref}
        className="relative grid gap-8 lg:grid-cols-[minmax(0,15rem)_minmax(0,1fr)_minmax(0,16rem)] lg:gap-x-14 xl:gap-x-20"
        data-testid="exposure-flow"
        data-focusing={active ? '' : undefined}
        {...containerProps}
      >
        {layout && (
          <svg
            aria-hidden
            className="pointer-events-none absolute inset-0 hidden h-full w-full overflow-visible lg:block"
            width={layout.width}
            height={layout.height}
          >
            {shown.map((s) => {
              const from = layout.out[`s:${s.id}`]
              const to = layout.in.ring
              if (!from || !to) return null
              const w = wireStroke(s.health)
              const k = `w:s:${s.id}`
              const d = wirePath(from.x + 6, from.y, to.x + 8, to.y)
              return (
                <g key={k} className={dimClass(active, lit(k))} data-wire={s.health}>
                  <path
                    d={d}
                    fill="none"
                    stroke={lit(k) ? 'var(--signal)' : w.stroke}
                    strokeWidth={wireWidth(s.received, maxSource)}
                    strokeDasharray={w.dash}
                    strokeLinecap="round"
                  />
                  {s.health === 'ok' && !reduced && (
                    <path
                      d={d}
                      fill="none"
                      stroke="var(--card, #fff)"
                      strokeOpacity={0.55}
                      strokeWidth={Math.max(1, wireWidth(s.received, maxSource) - 0.5)}
                      strokeDasharray="3 7"
                      className="animate-flow-dash"
                    />
                  )}
                </g>
              )
            })}
            {outcomes.map((o) => {
              const from = layout.out.ring
              const to = layout.in[`o:${o.key}`]
              if (!from || !to) return null
              const k = `w:o:${o.key}`
              const w = wireStroke(o.tone === 'bad' && o.fig.value > 0 ? 'bad' : 'neutral')
              return (
                <path
                  key={k}
                  className={dimClass(active, lit(k))}
                  d={wirePath(from.x - 8, from.y, to.x - 4, to.y)}
                  fill="none"
                  stroke={lit(k) ? 'var(--signal)' : w.stroke}
                  strokeWidth={wireWidth(o.fig.value, maxOutcome)}
                  strokeLinecap="round"
                />
              )
            })}
          </svg>
        )}

        {/* Sources */}
        <section aria-labelledby={`${tipId}-src`} className="relative min-w-0">
          <h3 id={`${tipId}-src`} className="mb-2 text-xs font-medium text-muted-foreground">
            {t('dashboardKit.flow.sources', 'Sources')}
            {intake && (
              <span className="ms-1.5 font-normal">
                {t('dashboardKit.flow.receivedIn', 'received in {period}', { period: periodLabel })}
              </span>
            )}
          </h3>
          {intake && shown.length > 0 ? (
            <ul className="grid gap-0.5 rounded-lg border border-dashed border-border-strong p-1.5">
              {shown.map((s) => {
                const k = `s:${s.id}`
                const note = healthNote(t, s, locale)
                const name = sourceName(t, s)
                return (
                  <li key={s.id}>
                    <FlowLink
                      to={s.drill}
                      className={cn(
                        'grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2 rounded-md px-2.5 py-1.5 hover:bg-muted/60 focus-visible:bg-muted/60',
                        dimClass(active, lit(k))
                      )}
                      data-wire-out={k}
                      {...bind(k)}
                    >
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium">{name}</span>{' '}
                        <span
                          className={cn(
                            'block truncate text-xs text-muted-foreground',
                            s.health === 'stale' && 'text-warning',
                            s.health === 'failed' && 'text-destructive'
                          )}
                        >
                          {originLabel(t, s.origin)}
                          {note && <span className="ms-1.5"> {note}</span>}
                        </span>
                      </span>{' '}
                      <span className="text-xl font-semibold tabular-nums leading-none">
                        {n(s.received)}
                      </span>
                    </FlowLink>
                  </li>
                )
              })}
              {more > 0 && (
                <li className="px-2.5 py-1 text-xs">
                  <FlowLink to={intake.drill} className="text-signal-text hover:underline">
                    {tCount(
                      t,
                      'dashboardKit.flow.moreSources',
                      '{count} more sources',
                      '{count} more source',
                      more,
                      { count: more }
                    )}
                  </FlowLink>
                </li>
              )}
            </ul>
          ) : (
            <p className="rounded-lg border border-dashed p-3 text-xs leading-relaxed text-muted-foreground">
              {result.intake_reason_key
                ? t(result.intake_reason_key)
                : t('dashboardKit.flow.noSources', 'No source sent findings in this period.')}
            </p>
          )}
        </section>

        {/* Core */}
        <div className="flex min-w-0 flex-col items-center gap-3">
          <div
            className={cn(
              'flex flex-wrap items-end justify-center gap-x-3 gap-y-1',
              dimClass(active, lit('funnel'))
            )}
            data-k="funnel"
          >
            {intake && (
              <>
                <FunnelFigure
                  label={t('dashboardKit.flow.funnel.received', 'Received')}
                  value={n(intake.totals.received)}
                  to={intake.drill}
                  bind={bind('f:received')}
                />
                <span className="pb-1 text-muted-foreground" aria-hidden>
                  →
                </span>
                <FunnelFigure
                  label={t('dashboardKit.flow.funnel.new', 'New or reopened')}
                  value={n(intake.noise.new)}
                  to={intake.drill}
                  bind={bind('f:new')}
                />
                <span className="pb-1 text-muted-foreground" aria-hidden>
                  →
                </span>
              </>
            )}
            <FunnelFigure
              label={t('dashboardKit.flow.funnel.actionable', 'Actionable')}
              value={n(actionableTotal)}
              to={result.actionable.drill}
              bind={bind('f:actionable')}
            />
          </div>

          <div
            className={cn('relative size-64 sm:size-72 xl:size-80', dimClass(active, lit('ring')))}
            data-k="ring"
          >
            <span className="absolute left-[12%] top-1/2 size-px" data-wire-in="ring" aria-hidden />
            <span
              className="absolute right-[12%] top-1/2 size-px"
              data-wire-out="ring"
              aria-hidden
            />
            <svg
              viewBox="-160 -160 320 320"
              className="size-full overflow-visible"
              role="group"
              aria-label={t('dashboardKit.flow.ringLabel', 'Actionable findings by priority class')}
            >
              <circle r={R} fill="none" stroke="var(--border)" strokeWidth={arcs.length ? 0 : 18} />
              {arcs.map((a) => {
                const k = `p:${a.key}`
                const share =
                  actionableTotal > 0 ? Math.round((100 * a.value) / actionableTotal) : 0
                const fig = result.classes.find((c) => c.key === a.key)
                return (
                  <g key={a.key} className={dimClass(active, lit(k))}>
                    <path
                      d={a.d}
                      fill="none"
                      stroke={a.color}
                      strokeWidth={lit(k) ? 24 : 18}
                      className="cursor-pointer outline-none transition-[stroke-width] duration-200 focus-visible:[stroke-width:24] motion-reduce:transition-none"
                      role="link"
                      tabIndex={0}
                      aria-label={t(
                        'dashboardKit.flow.arcAria',
                        '{class}: {count} findings, {share}% of actionable',
                        {
                          class: classLabel(a.key),
                          count: n(a.value),
                          share,
                        }
                      )}
                      {...bind(k, '[data-k="ring"]')}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && fig?.drill) router.push(fig.drill)
                      }}
                      onClick={(e) => {
                        const b = bind(k, '[data-k="ring"]')
                        b.onClick(e)
                        if (!e.defaultPrevented && fig?.drill) router.push(fig.drill)
                      }}
                    />
                    <text
                      x={a.labelX}
                      y={a.labelY}
                      textAnchor="middle"
                      dominantBaseline="middle"
                      className="fill-foreground text-xs font-semibold tabular-nums"
                      aria-hidden
                    >
                      <tspan className="fill-muted-foreground">{a.key} </tspan>
                      {n(a.value)}
                    </text>
                  </g>
                )
              })}
            </svg>
            <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
              <span className="text-xs font-medium text-muted-foreground">
                {activeClass?.key ?? t('dashboardKit.flow.funnel.actionable', 'Actionable')}
              </span>
              <span
                className={cn(
                  'text-5xl font-semibold leading-none tracking-tight tabular-nums',
                  activeClass && 'text-signal-text'
                )}
                data-testid="flow-centre"
              >
                {n(centreValue)}
              </span>
              <span className="text-xs text-muted-foreground">
                {t('dashboardKit.flow.byClass', 'by priority class')}
              </span>
            </div>
          </div>

          {result.stages && (
            <StageRow stages={result.stages.stages} focus={result.stages.focus ?? null} />
          )}
        </div>

        {/* Outcomes */}
        <section aria-labelledby={`${tipId}-out`} className="relative min-w-0">
          <h3 id={`${tipId}-out`} className="mb-2 text-xs font-medium text-muted-foreground">
            {t('dashboardKit.flow.outcomes', 'Outcomes')}
          </h3>
          <ul className="grid gap-0.5">
            {outcomes.map((o, i) => {
              const k = `o:${o.key}`
              return (
                <li key={o.key}>
                  {i === 3 && (
                    <p className="mb-0.5 mt-2 px-2.5 text-xs text-muted-foreground">
                      {t('dashboardKit.flow.closedIn', 'Closed in {period}', {
                        period: periodLabel,
                      })}
                    </p>
                  )}
                  <FlowLink
                    to={o.fig.drill}
                    className={cn(
                      'grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-2.5 gap-y-1 rounded-md px-2.5 py-1.5 hover:bg-muted/60 focus-visible:bg-muted/60',
                      o.sub && 'ps-6',
                      dimClass(active, lit(k))
                    )}
                    data-wire-in={k}
                    {...bind(k)}
                  >
                    <span className={cn('truncate text-sm', o.sub && 'text-muted-foreground')}>
                      {o.label}
                    </span>{' '}
                    <span
                      className={cn(
                        'text-right font-semibold tabular-nums leading-none',
                        o.sub ? 'text-base' : 'text-xl', // anatomy-ok: a sub-row figure is one step under its outcome
                        o.tone === 'bad' && o.fig.value > 0 && 'text-destructive'
                      )}
                    >
                      {n(o.fig.value)}
                    </span>
                    {o.key === 'open' && result.open.value > 0 && (
                      <span
                        className="col-span-2 flex h-[3px] gap-0.5 overflow-hidden rounded-sm"
                        aria-hidden
                      >
                        {result.severity.map((r) => (
                          <span
                            key={r.key}
                            style={{
                              flex: r.value,
                              background:
                                SEVERITY_CHART_COLORS[
                                  (r.key ?? '') as keyof typeof SEVERITY_CHART_COLORS
                                ] ?? 'var(--muted-foreground)',
                            }}
                          />
                        ))}
                      </span>
                    )}
                  </FlowLink>
                </li>
              )
            })}
          </ul>
          {intake && (
            <div className="mt-3 grid gap-1 px-2.5 text-xs text-muted-foreground">
              <span>
                <FlowLink
                  to={intake.drill}
                  className="text-foreground underline decoration-border-strong underline-offset-2"
                >
                  {n(intake.totals.still_detected)}
                </FlowLink>{' '}
                {t('dashboardKit.flow.stillDetected', 'still detected on import')}
              </span>
              <span>
                <FlowLink
                  to={intake.drill}
                  className="text-foreground underline decoration-border-strong underline-offset-2"
                >
                  {n(intake.totals.suppressed)}
                </FlowLink>{' '}
                {t('dashboardKit.flow.removedByRules', 'removed by rules')}
              </span>
            </div>
          )}
        </section>

        <FlowTip id={tipId} content={tip} anchor={anchor} />
      </div>
      <div className="flex flex-wrap justify-between gap-x-4 gap-y-1 border-t pt-2 text-xs text-muted-foreground">
        <span className="flex flex-wrap gap-x-4 gap-y-1">
          <span>
            {scope === 'organization'
              ? t('dashboardKit.flow.scopeOrg', 'Organization figures')
              : t('dashboardKit.flow.scopeMine', 'Counts in your data scope')}
          </span>
          {result.intake && scope !== 'organization' && (
            <span>{t('dashboardKit.flow.sourcesOrg', 'Sources are organization figures')}</span>
          )}
        </span>
        <span>{t('dashboardKit.flow.everyNumber', 'Every number opens its list')}</span>
      </div>
    </div>
  )
}

function FunnelFigure({
  label,
  value,
  to,
  bind,
}: {
  label: string
  value: string
  to: string | null | undefined
  bind: Record<string, unknown>
}) {
  return (
    <FlowLink to={to} className="grid justify-items-center hover:underline" {...bind}>
      <span className="text-xs text-muted-foreground">{label}</span>{' '}
      <span className="text-2xl font-semibold leading-tight tabular-nums">{value}</span>
    </FlowLink>
  )
}

function StageRow({ stages, focus }: { stages: Stage[]; focus: number | null }) {
  const { t, locale } = useTranslation()
  return (
    <ol
      className="relative grid w-full max-w-[32rem] grid-cols-5 before:absolute before:inset-x-[10%] before:top-[11px] before:h-px before:bg-border"
      aria-label={t('dashboardKit.flow.stagesLabel', 'CTEM stage health')}
    >
      {stages.map((s, i) => {
        const current = focus === i
        const name = s.label_key ? t(s.label_key, s.label ?? s.key) : (s.label ?? s.key)
        const value = formatMetric(s.value, s.unit ?? 'count', locale)
        return (
          <li
            key={s.key}
            className="relative grid justify-items-center gap-1 text-center text-xs"
            aria-current={current ? 'step' : undefined}
          >
            <span
              className={cn(
                'grid size-[22px] place-items-center rounded-full border bg-card',
                s.state === 'good' && 'border-success text-success',
                s.state === 'warn' && 'border-warning text-warning',
                s.state === 'crit' && 'border-destructive text-destructive',
                s.state === 'unmeasured' && 'border-border-strong text-muted-foreground',
                current && 'border-signal bg-signal text-signal-ink'
              )}
              aria-hidden
            >
              {STAGE_GLYPH[s.state]}
            </span>
            <span className="truncate">{name}</span>
            <FlowLink
              to={s.drill}
              label={`${name}: ${value}`}
              className={cn(
                'font-semibold tabular-nums hover:underline',
                s.value == null && 'text-muted-foreground'
              )}
            >
              {value}
            </FlowLink>
          </li>
        )
      })}
    </ol>
  )
}

/** The flow as tables: the same figures, each a link. */
function FlowTable({ result }: { result: FlowResult }) {
  const { t, locale } = useTranslation()
  const n = (v: number) => formatCount(v, locale)
  const row = (label: string, fig: FlowFigure) => (
    <tr key={label} className="border-b last:border-0">
      <th scope="row" className="py-1.5 pe-3 text-left font-normal">
        {label}
      </th>
      <td className="py-1.5 text-right tabular-nums">
        <FlowLink to={fig.drill} className="hover:underline">
          {n(fig.value)}
        </FlowLink>
      </td>
    </tr>
  )
  const intake = result.intake
  return (
    <div className="grid gap-4 text-sm md:grid-cols-2">
      {intake && (
        <table className="w-full">
          <caption className="mb-1 text-left text-xs font-medium text-muted-foreground">
            {t('dashboardKit.flow.sources', 'Sources')}
          </caption>
          <tbody>
            {intake.sources.map((s) =>
              row(`${sourceName(t, s)} (${originLabel(t, s.origin)})`, {
                value: s.received,
                drill: s.drill,
              })
            )}
            {row(t('dashboardKit.flow.funnel.received', 'Received'), {
              value: intake.totals.received,
              drill: intake.drill,
            })}
            {row(t('dashboardKit.flow.funnel.new', 'New or reopened'), {
              value: intake.noise.new,
              drill: intake.drill,
            })}
          </tbody>
        </table>
      )}
      <table className="w-full">
        <caption className="mb-1 text-left text-xs font-medium text-muted-foreground">
          {t('dashboardKit.flow.ringLabel', 'Actionable findings by priority class')}
        </caption>
        <tbody>
          {result.classes.map((c) => row(c.key ?? '', c))}
          {row(t('dashboardKit.flow.funnel.actionable', 'Actionable'), result.actionable)}
        </tbody>
      </table>
      <table className="w-full">
        <caption className="mb-1 text-left text-xs font-medium text-muted-foreground">
          {t('dashboardKit.flow.outcomes', 'Outcomes')}
        </caption>
        <tbody>
          {row(t('dashboardKit.flow.outcome.open', 'Open'), result.open)}
          {result.severity.map((r) => row(t(`severity.${r.key}`, r.key ?? ''), r))}
          {row(t('dashboardKit.flow.outcome.pastSla', 'Past SLA'), result.past_sla)}
          {row(t('dashboardKit.flow.outcome.inProgress', 'In progress'), result.in_progress)}
          {row(t('dashboardKit.flow.outcome.fixed', 'Fixed'), result.fixed)}
          {row(t('dashboardKit.flow.outcome.accepted', 'Accepted'), result.accepted)}
          {row(
            t('dashboardKit.flow.outcome.falsePositive', 'False positive'),
            result.false_positive
          )}
        </tbody>
      </table>
    </div>
  )
}
