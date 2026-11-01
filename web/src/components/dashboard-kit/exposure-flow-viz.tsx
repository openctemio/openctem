'use client'

/**
 * The exposure flow (metric exposure.flow; api docs/architecture/dashboards.md,
 * "Exposure flow and intake"): sources on the left, the CTEM core in the
 * middle (findings received to new, a labelled ring of actionable findings by
 * priority class, the five stages), outcomes on the right. Every figure is a
 * link to the list it counts, and each figure is shown once.
 *
 * Hover, keyboard focus or a first tap lights an element and its path, dims
 * the rest and opens a tooltip (definition, figures, the list). The layout
 * follows the widget's own width (container queries, `flowBand`): three
 * bounded columns from 960 px, the core beside the outcomes with the sources
 * above from 660 px. Below that (a phone) the answer comes first: actionable
 * now with its priority split as one bar and four figures, the outcomes as a
 * grid, the stages as a list with their state in words, then the sources.
 * Sources are a ranked bar list (RankedBars) by findings or assets, by tool or
 * by instance. Wires are drawn between measured rows. "Show table" gives the
 * same figures as tables. Research: research/359-exposure-flow-phone.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useTranslation } from '@/context/i18n-provider'
import { SegmentedLens } from '@/features/shared/components/segmented-lens'
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
  flowBand,
  useElementWidth,
  useFlowFocus,
  useWireAnchors,
  wirePath,
  wireStroke,
  wireWidth,
  type FlowTipContent,
} from './flow-parts'
import { RankedBars, type RankedBarRow } from './ranked-bars'
import { StackedBar } from './stacked-bar'
import { ActHere, StageStateIcon, useStageStateText } from './stage-state'
import { ChartOrTable, usePrefersReducedMotion } from './viz-parts'
import type {
  FlowFigure,
  FlowResult,
  IntakeInstance,
  IntakeSourceRow,
  SourceHealth,
  Stage,
} from './types'

// A lens over one widget's own ranking, not a list's filter.
const WidgetLens = SegmentedLens // anatomy-ok: ranks and groups the sources inside one dashboard widget

/** Source rows with a value before "Show all": wide and mid cards, a phone. */
const MAX_SOURCES = 6
const MAX_SOURCES_PHONE = 5

/** An intake figure in a line of text: a whole phrase, 44 px tall on a phone or a touch screen. */
const INTAKE_LINK = 'inline-flex min-h-7 items-center hover:underline pointer-coarse:min-h-11'
const INTAKE_LINK_PHONE = 'inline-flex min-h-11 items-center hover:underline'

/** Where the viewer's source view (measure, grouping) is remembered. */
const SOURCE_VIEW_KEY = 'openctem.dashboard.flow.sources'

type Translate = ReturnType<typeof useTranslation>['t']
type Measure = 'findings' | 'assets'
type Grouping = 'tool' | 'instance'

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
    case 'platform':
      return t('dashboardKit.flow.origin.platform', 'Platform')
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
export function healthNote(
  t: Translate,
  s: { health: SourceHealth; last_at: string | null },
  locale: string
): string | null {
  if (s.health === 'ok') return null
  const when = formatRelativeTime(s.last_at, locale)
  return s.health === 'failed'
    ? t('dashboardKit.flow.health.failed', 'Failed {when}', { when })
    : t('dashboardKit.flow.health.stale', 'Stale, last {when}', { when })
}

const HEALTH_RANK: Record<SourceHealth, number> = { ok: 0, stale: 1, failed: 2 }

/** The worst of two healths. */
function worst(a: SourceHealth, b: SourceHealth): SourceHealth {
  return HEALTH_RANK[b] > HEALTH_RANK[a] ? b : a
}

/** One instance with what it fed, summed over the tools it reported for. */
export interface InstanceGroup {
  key: string
  instance: IntakeInstance
  received: number
  assets: number
  health: SourceHealth
  last_at: string | null
  tools: Array<{ name: string; received: number; assets: number }>
}

/** The sources regrouped by instance (sensor, CI project, connector, platform). */
export function groupByInstance(t: Translate, sources: IntakeSourceRow[]): InstanceGroup[] {
  const out = new Map<string, InstanceGroup>()
  for (const s of sources) {
    for (const i of s.instances ?? []) {
      const key = `${i.kind}:${i.id}`
      const g = out.get(key) ?? {
        key,
        instance: i,
        received: 0,
        assets: 0,
        health: 'ok' as SourceHealth,
        last_at: null as string | null,
        tools: [],
      }
      g.received += i.received
      g.assets += i.assets ?? 0
      g.health = worst(g.health, i.health)
      if (i.last_at && (!g.last_at || i.last_at > g.last_at)) g.last_at = i.last_at
      g.tools.push({ name: sourceName(t, s), received: i.received, assets: i.assets ?? 0 })
      out.set(key, g)
    }
  }
  return [...out.values()]
}

function readSourceView(): { measure?: Measure; group?: Grouping } {
  try {
    const raw = window.localStorage.getItem(SOURCE_VIEW_KEY)
    if (!raw) return {}
    const v = JSON.parse(raw) as { measure?: unknown; group?: unknown }
    return {
      measure: v.measure === 'assets' || v.measure === 'findings' ? v.measure : undefined,
      group: v.group === 'instance' || v.group === 'tool' ? v.group : undefined,
    }
  } catch {
    return {}
  }
}

function writeSourceView(v: { measure: Measure; group: Grouping }) {
  try {
    window.localStorage.setItem(SOURCE_VIEW_KEY, JSON.stringify(v))
  } catch {
    // Private mode or blocked storage: the view is not remembered.
  }
}

/** The viewer's source view, remembered on this browser. */
function useSourceView(): [Measure, Grouping, (m: Measure) => void, (g: Grouping) => void] {
  const [measure, setMeasure] = useState<Measure>('findings')
  const [group, setGroup] = useState<Grouping>('tool')
  useEffect(() => {
    const v = readSourceView()
    if (v.measure) setMeasure(v.measure)
    if (v.group) setGroup(v.group)
  }, [])
  const pickMeasure = useCallback(
    (m: Measure) => {
      setMeasure(m)
      writeSourceView({ measure: m, group })
    },
    [group]
  )
  const pickGroup = useCallback(
    (g: Grouping) => {
      setGroup(g)
      writeSourceView({ measure, group: g })
    },
    [measure]
  )
  return [measure, group, pickMeasure, pickGroup]
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

function classColor(key: string | undefined): string {
  return isPriorityClass(key) ? PRIORITY_CHART_COLORS[key] : 'var(--muted-foreground)'
}

function severityColor(key: string | undefined): string {
  return (
    SEVERITY_CHART_COLORS[(key ?? '') as keyof typeof SEVERITY_CHART_COLORS] ??
    'var(--muted-foreground)'
  )
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
      color: classColor(c.key),
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

interface Outcome {
  key: string
  label: string
  fig: FlowFigure
  sub?: boolean
  tone?: 'bad'
}

function FlowChart({ result, scope }: { result: FlowResult; scope?: 'organization' | 'personal' }) {
  const { t, locale } = useTranslation()
  const n = (v: number) => formatCount(v, locale)
  const ref = useRef<HTMLDivElement>(null)
  const router = useRouter()
  const reduced = usePrefersReducedMotion()
  const { active, anchor, tipId, bind, containerProps } = useFlowFocus(ref)
  const [measure, group, setMeasure, setGroup] = useSourceView()
  const intake = result.intake
  const sources = useMemo(() => intake?.sources ?? [], [intake])
  // The band comes from the visual's own width first, so the rows it shows
  // exist before the wires measure them.
  const band = flowBand(useElementWidth(ref))
  const narrow = band === 'narrow'
  const hasAssets = sources.some((s) => (s.assets ?? 0) > 0)
  const hasInstances = sources.some((s) => (s.instances?.length ?? 0) > 0)
  const m: Measure = hasAssets ? measure : 'findings'
  const g: Grouping = hasInstances ? group : 'tool'
  const layout = useWireAnchors(ref, `${band}:${m}:${g}:${sources.length}:${result.open.value}`)
  const arcs = useMemo(() => ringArcs(result.classes), [result.classes])
  const actionableTotal = result.actionable.value
  const periodLabel = t('dashboardKit.flow.period', '{days} days', { days: result.days })
  const instances = useMemo(() => groupByInstance(t, sources), [t, sources])

  const outcomes: Outcome[] = [
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
  const outcome = (key: string) => outcomes.find((o) => o.key === key) as Outcome

  const maxSource = Math.max(1, ...sources.map((s) => s.received))
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

  const activeClass = active?.startsWith('p:')
    ? result.classes.find((c) => `p:${c.key}` === active)
    : undefined

  const viewFindings = (count: number) =>
    tCount(
      t,
      'dashboardKit.flow.tip.viewFindings',
      'View {count} findings',
      'View {count} finding',
      count,
      {
        count: n(count),
      }
    )
  const viewReceipts = (count: number) =>
    tCount(
      t,
      'dashboardKit.flow.tip.viewReceipts',
      'View {count} receipts',
      'View {count} receipt',
      count,
      {
        count: n(count),
      }
    )
  const sensorActivity = (insts: IntakeInstance[] | undefined) => {
    const sensors = (insts ?? []).filter((i) => i.kind === 'sensor')
    if (sensors.length === 0) return undefined
    return [
      {
        label: t('dashboardKit.flow.tip.sensorActivity', 'Per-sensor activity'),
        href: sensors.length === 1 && sensors[0].sensor_href ? sensors[0].sensor_href : '/sensors',
      },
    ]
  }

  const tip = ((): FlowTipContent | null => {
    if (!active) return null
    if (active.startsWith('s:')) {
      const s = sources.find((x) => `s:${x.id}` === active)
      if (!s) return null
      const total = m === 'assets' ? (s.assets ?? 0) : s.received
      const rows: Array<[string, string]> = [
        [t('dashboardKit.flow.tip.received', 'Findings received'), n(s.received)],
        [t('dashboardKit.flow.tip.newOrReopened', 'New or reopened'), n(s.created + s.reopened)],
        [t('dashboardKit.flow.tip.seenAgain', 'Seen again'), n(s.still_detected)],
        [t('dashboardKit.flow.tip.notStored', 'Not stored'), n(s.not_stored)],
      ]
      if (s.assets != null && s.assets > 0) {
        rows.push([t('dashboardKit.flow.tip.assets', 'Assets discovered or updated'), n(s.assets)])
      }
      rows.push([
        t('dashboardKit.flow.tip.lastReceipt', 'Last receipt'),
        formatRelativeTime(s.last_at, locale),
      ])
      for (const i of s.instances ?? []) {
        const v = m === 'assets' ? (i.assets ?? 0) : i.received
        const share = total > 0 ? Math.round((100 * v) / total) : 0
        const note = healthNote(t, i, locale)
        rows.push([toDisplayText(i.name, 60), `${n(v)} (${share}%)${note ? `, ${note}` : ''}`])
      }
      return {
        title: sourceName(t, s),
        rows,
        definition:
          s.kind === 'platform'
            ? t(
                'dashboardKit.flow.tip.platformDef',
                'Findings the platform derived while ingesting other reports (for example a known-vulnerable version on a discovered service). An organization figure.'
              )
            : t(
                'dashboardKit.flow.tip.sourceDef',
                'Findings this source reported in the period, from its import and run receipts. An organization figure.'
              ),
        link: { label: viewReceipts(s.receipts), href: s.drill },
        more: sensorActivity(s.instances),
      }
    }
    if (active.startsWith('i:')) {
      const gr = instances.find((x) => `i:${x.key}` === active)
      if (!gr) return null
      return {
        title: toDisplayText(gr.instance.name, 80),
        rows: [
          [t('dashboardKit.flow.tip.received', 'Findings received'), n(gr.received)],
          [t('dashboardKit.flow.tip.assets', 'Assets discovered or updated'), n(gr.assets)],
          ...gr.tools.map((x): [string, string] => [
            x.name,
            n(m === 'assets' ? x.assets : x.received),
          ]),
          [
            t('dashboardKit.flow.tip.lastReceipt', 'Last receipt'),
            formatRelativeTime(gr.last_at, locale),
          ],
        ],
        definition: t(
          'dashboardKit.flow.tip.instanceDef',
          'What this instance sent in the period, over every tool it ran. An organization figure.'
        ),
        link: gr.instance.sensor_href
          ? {
              label: t('dashboardKit.flow.tip.sensorActivity', 'Per-sensor activity'),
              href: gr.instance.sensor_href,
            }
          : undefined,
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
        link: { label: viewFindings(c.value), href: c.drill },
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
        link: { label: viewFindings(o.fig.value), href: o.fig.drill },
      }
    }
    if (active === 'f:actionable') {
      return {
        title: t('dashboardKit.flow.funnel.actionable', 'Actionable now'),
        rows: [[t('dashboardKit.flow.tip.findings', 'Findings'), n(actionableTotal)]],
        definition: t('dashboardKit.flow.funnelDef.actionable', ''),
        link: { label: viewFindings(actionableTotal), href: result.actionable.drill },
      }
    }
    if (active.startsWith('f:') && intake) {
      const which = active.slice(2) === 'new' ? 'new' : 'received'
      const v = which === 'new' ? intake.noise.new : intake.totals.received
      return {
        title: t(`dashboardKit.flow.funnel.${which}`, which),
        rows: [[t('dashboardKit.flow.tip.findings', 'Findings'), n(v)]],
        definition: t(`dashboardKit.flow.funnelDef.${which}`, ''),
        link: { label: viewReceipts(intake.totals.receipts), href: intake.drill },
      }
    }
    return null
  })()

  const centreValue = activeClass ? activeClass.value : actionableTotal

  // ---- Sources: a ranked bar list ----
  const unit = (count: number) =>
    m === 'assets'
      ? tCount(t, 'dashboardKit.flow.unit.assets', '{count} assets', '{count} asset', count, {
          count: n(count),
        })
      : tCount(t, 'dashboardKit.flow.unit.findings', '{count} findings', '{count} finding', count, {
          count: n(count),
        })
  const sourceRows: RankedBarRow[] =
    g === 'instance'
      ? instances.map((gr) => {
          const value = m === 'assets' ? gr.assets : gr.received
          const name = toDisplayText(gr.instance.name, 80)
          const chip = originLabel(t, gr.instance.kind)
          return {
            key: `i:${gr.key}`,
            label: name,
            chip,
            value,
            display: n(value),
            href: gr.instance.sensor_href ?? null,
            health: gr.health,
            note: healthNote(t, gr, locale),
            aria: `${name}, ${chip}: ${unit(value)}`,
          }
        })
      : sources.map((s) => {
          const value = m === 'assets' ? (s.assets ?? 0) : s.received
          const name = sourceName(t, s)
          const chip = originLabel(t, s.origin)
          return {
            key: `s:${s.id}`,
            label: name,
            chip,
            value,
            display: n(value),
            href: s.drill,
            health: s.health,
            note: healthNote(t, s, locale),
            aria: `${name}, ${chip}: ${unit(value)}`,
          }
        })

  const sourcesBlock = (
    <section
      aria-labelledby={`${tipId}-src`}
      className="relative min-w-0 @min-[660px]:col-span-2 @min-[960px]:col-span-1"
      data-testid="flow-sources"
    >
      <h3 id={`${tipId}-src`} className="mb-1 text-xs font-medium text-muted-foreground">
        {t('dashboardKit.flow.sources', 'Sources')}
        <span className="ms-1.5 font-normal">
          {scope === 'organization'
            ? t('dashboardKit.flow.sourcesWindow', 'in {period}', { period: periodLabel })
            : t('dashboardKit.flow.sourcesWindowOrg', 'in {period}, organization figures', {
                period: periodLabel,
              })}
        </span>
      </h3>
      {intake && narrow && (
        <p
          className={cn('flex flex-wrap gap-x-4 text-xs', dimClass(active, lit('funnel')))}
          data-testid="flow-funnel-line"
        >
          <FlowLink
            to={intake.drill}
            className={narrow ? INTAKE_LINK_PHONE : INTAKE_LINK}
            {...bind('f:received')}
          >
            {tCount(
              t,
              'dashboardKit.flow.funnelLine.received',
              '{count} findings received',
              '{count} finding received',
              intake.totals.received,
              { count: n(intake.totals.received) }
            )}
          </FlowLink>
          <FlowLink
            to={intake.drill}
            className={narrow ? INTAKE_LINK_PHONE : INTAKE_LINK}
            {...bind('f:new')}
          >
            {t('dashboardKit.flow.funnelLine.new', '{count} new or reopened', {
              count: n(intake.noise.new),
            })}
          </FlowLink>
        </p>
      )}
      {intake && (hasAssets || hasInstances) && (
        <div className="mb-1 flex flex-wrap gap-2">
          {hasAssets && (
            <WidgetLens
              label={t('dashboardKit.flow.measure.label', 'Rank sources by')}
              value={m}
              onChange={setMeasure}
              options={[
                { value: 'findings', label: t('dashboardKit.flow.measure.findings', 'Findings') },
                { value: 'assets', label: t('dashboardKit.flow.measure.assets', 'Assets') },
              ]}
            />
          )}
          {hasInstances && (
            <WidgetLens
              label={t('dashboardKit.flow.group.label', 'Group sources by')}
              value={g}
              onChange={setGroup}
              options={[
                { value: 'tool', label: t('dashboardKit.flow.group.tool', 'Tool') },
                {
                  value: 'instance',
                  label: t('dashboardKit.flow.group.instance', 'Source instance'),
                },
              ]}
            />
          )}
        </div>
      )}
      {intake && sourceRows.length > 0 ? (
        <RankedBars
          rows={sourceRows}
          limit={narrow ? MAX_SOURCES_PHONE : MAX_SOURCES}
          label={t('dashboardKit.flow.sources', 'Sources')}
          resetKey={`${m}:${g}`}
          listClassName="@min-[660px]:grid-cols-2 @min-[660px]:gap-x-4 @min-[960px]:grid-cols-1"
          zeroLabel={(count) =>
            tCount(
              t,
              'dashboardKit.flow.zeroSources',
              '+{count} sources with nothing in {period}',
              '+{count} source with nothing in {period}',
              count,
              { count, period: periodLabel }
            )
          }
          rowProps={(r) => ({
            className: dimClass(active, lit(r.key)),
            ...(r.key.startsWith('s:') ? { 'data-wire-out': r.key } : {}),
            ...bind(r.key),
          })}
        />
      ) : (
        <p className="rounded-lg border border-dashed p-3 text-xs leading-relaxed text-muted-foreground">
          {result.intake_reason_key
            ? t(result.intake_reason_key)
            : t('dashboardKit.flow.noSources', 'No source sent findings in this period.')}
        </p>
      )}
      {intake && (
        <p className="flex flex-wrap gap-x-4 px-2 text-xs text-muted-foreground">
          <FlowLink to={intake.drill} className={narrow ? INTAKE_LINK_PHONE : INTAKE_LINK}>
            {t('dashboardKit.flow.stillDetectedLine', '{count} still detected on import', {
              count: n(intake.totals.still_detected),
            })}
          </FlowLink>
          <FlowLink to={intake.drill} className={narrow ? INTAKE_LINK_PHONE : INTAKE_LINK}>
            {t('dashboardKit.flow.removedByRulesLine', '{count} removed by rules', {
              count: n(intake.totals.suppressed),
            })}
          </FlowLink>
        </p>
      )}
    </section>
  )

  // ---- Core ----
  const classTiles = (
    <div className="grid grid-cols-4 gap-1">
      {result.classes.map((c) => {
        const k = `p:${c.key}`
        return (
          <FlowLink
            key={c.key}
            to={c.drill}
            label={t('dashboardKit.flow.classAria', '{class}: {count} actionable findings', {
              class: c.key ?? '',
              count: n(c.value),
            })}
            className={cn(
              'grid min-h-11 content-center justify-items-start rounded-md bg-muted/40 px-2 py-1.5 hover:bg-muted',
              dimClass(active, lit(k))
            )}
            {...bind(k)}
          >
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <span
                className="size-2 rounded-full"
                style={{ background: classColor(c.key) }}
                aria-hidden
              />
              {c.key}
            </span>{' '}
            <span className="text-base font-semibold tabular-nums leading-tight">{n(c.value)}</span>
          </FlowLink>
        )
      })}
    </div>
  )

  const headline = (
    <div
      className={cn('grid w-full gap-2', dimClass(active, lit('ring')))}
      data-k="ring"
      data-testid="flow-headline"
    >
      <FlowLink
        to={result.actionable.drill}
        className="grid w-fit justify-items-start hover:underline"
        {...bind('f:actionable')}
      >
        <span className="text-xs font-medium text-muted-foreground">
          {t('dashboardKit.flow.funnel.actionable', 'Actionable now')}
        </span>{' '}
        <span
          className="text-4xl font-semibold leading-none tracking-tight tabular-nums"
          data-testid="flow-centre"
        >
          {n(actionableTotal)}
        </span>
      </FlowLink>
      <span className="text-xs text-muted-foreground">
        {t(
          'dashboardKit.flow.headline.caption',
          'Open findings with a priority class, counted now'
        )}
      </span>
      <StackedBar
        parts={result.classes.map((c) => ({
          key: c.key ?? '',
          value: c.value,
          color: classColor(c.key),
        }))}
        className="h-2.5"
        testId="flow-priority-bar"
      />
      {classTiles}
    </div>
  )

  const ring = (
    <div
      className={cn('relative size-[clamp(15rem,24cqi,26rem)]', dimClass(active, lit('ring')))}
      data-k="ring"
    >
      <span className="absolute left-[12%] top-1/2 size-px" data-wire-in="ring" aria-hidden />
      <span className="absolute right-[12%] top-1/2 size-px" data-wire-out="ring" aria-hidden />
      <svg
        viewBox="-160 -160 320 320"
        className="size-full overflow-visible"
        role="group"
        aria-label={t('dashboardKit.flow.ringLabel', 'Actionable findings by priority class')}
      >
        <circle r={R} fill="none" stroke="var(--border)" strokeWidth={arcs.length ? 0 : 18} />
        {arcs.map((a) => {
          const k = `p:${a.key}`
          const share = actionableTotal > 0 ? Math.round((100 * a.value) / actionableTotal) : 0
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
                    class: a.key,
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
      <div className="absolute inset-0 grid place-content-center text-center">
        <FlowLink
          to={activeClass ? activeClass.drill : result.actionable.drill}
          className="grid justify-items-center rounded-full hover:underline"
          {...bind('f:actionable')}
        >
          <span className="text-xs font-medium text-muted-foreground">
            {activeClass?.key ?? t('dashboardKit.flow.funnel.actionable', 'Actionable now')}
          </span>{' '}
          <span
            className={cn(
              'text-[clamp(2.25rem,4.5cqi,3rem)] font-semibold leading-none tracking-tight tabular-nums',
              activeClass && 'text-signal-text'
            )}
            data-testid="flow-centre"
          >
            {n(centreValue)}
          </span>{' '}
          <span className="text-xs text-muted-foreground">
            {t('dashboardKit.flow.byClass', 'by priority class')}
          </span>
        </FlowLink>
      </div>
    </div>
  )

  const funnel = intake && (
    <div
      className={cn(
        'flex flex-wrap items-end justify-center gap-x-3 gap-y-1',
        dimClass(active, lit('funnel'))
      )}
      data-k="funnel"
    >
      <FunnelFigure
        label={t('dashboardKit.flow.funnel.received', 'Findings received')}
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
    </div>
  )

  const stages = result.stages && (
    <StageRow stages={result.stages.stages} focus={result.stages.focus ?? null} narrow={narrow} />
  )

  const core = (
    <div className="flex min-w-0 flex-col items-center gap-3">
      {narrow ? (
        headline
      ) : (
        <>
          {funnel}
          {ring}
          {stages}
        </>
      )}
    </div>
  )

  // ---- Outcomes ----
  const tile = (o: Outcome, className?: string) => {
    const k = `o:${o.key}`
    return (
      <FlowLink
        key={o.key}
        to={o.fig.drill}
        className={cn(
          'grid min-h-11 content-center gap-0.5 rounded-md bg-muted/40 px-2.5 py-1.5 hover:bg-muted',
          dimClass(active, lit(k)),
          className
        )}
        data-wire-in={k}
        {...bind(k)}
      >
        <span className="truncate text-xs text-muted-foreground">{o.label}</span>{' '}
        <span
          className={cn(
            'text-xl font-semibold tabular-nums leading-tight',
            o.tone === 'bad' && o.fig.value > 0 && 'text-destructive'
          )}
        >
          {n(o.fig.value)}
        </span>
        {o.key === 'open' && result.open.value > 0 && (
          <StackedBar
            parts={result.severity.map((r) => ({
              key: r.key ?? '',
              value: r.value,
              color: severityColor(r.key),
            }))}
            className="h-[3px] rounded-sm"
          />
        )}
      </FlowLink>
    )
  }

  const outcomesBlock = (
    <section
      aria-labelledby={`${tipId}-out`}
      className="relative min-w-0"
      data-testid="flow-outcomes"
    >
      <h3 id={`${tipId}-out`} className="mb-2 text-xs font-medium text-muted-foreground">
        {t('dashboardKit.flow.outcomes', 'Outcomes')}
      </h3>
      {narrow ? (
        <div className="grid gap-1">
          <div className="grid grid-cols-2 gap-1">
            {tile(outcome('past_sla'))}
            {tile(outcome('in_progress'))}
            {tile(outcome('open'), 'col-span-2')}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {t('dashboardKit.flow.closedIn', 'Closed in {period}', { period: periodLabel })}
          </p>
          <div className="grid grid-cols-3 gap-1">
            {tile(outcome('fixed'))}
            {tile(outcome('accepted'))}
            {tile(outcome('false_positive'))}
          </div>
        </div>
      ) : (
        <ul className="grid gap-0.5">
          {outcomes.map((o, i) => {
            const k = `o:${o.key}`
            return (
              <li key={o.key}>
                {i === 3 && (
                  <p className="mb-0.5 mt-2 px-2.5 text-xs text-muted-foreground">
                    {t('dashboardKit.flow.closedIn', 'Closed in {period}', { period: periodLabel })}
                  </p>
                )}
                <FlowLink
                  to={o.fig.drill}
                  className={cn(
                    'grid min-h-11 grid-cols-[minmax(0,1fr)_auto] content-center items-center gap-x-2.5 gap-y-1 rounded-md px-2.5 py-1.5 hover:bg-muted/60 focus-visible:bg-muted/60',
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
                    <StackedBar
                      parts={result.severity.map((r) => ({
                        key: r.key ?? '',
                        value: r.value,
                        color: severityColor(r.key),
                      }))}
                      className="col-span-2 h-[3px] rounded-sm"
                    />
                  )}
                </FlowLink>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )

  const wireSources = band === 'wide' && g === 'tool' ? sources : []

  return (
    <div className="@container flex flex-col gap-4">
      <div
        ref={ref}
        className={cn(
          'relative grid gap-5',
          // mid: the core beside the outcomes (core at the left edge, outcomes at
          // the right edge), the sources a row above.
          '@min-[660px]:grid-cols-[clamp(16rem,46cqi,32rem)_clamp(13rem,30cqi,22rem)] @min-[660px]:justify-between @min-[660px]:gap-x-[clamp(2.5rem,7cqi,5rem)]',
          // wide: sources at the left edge, outcomes at the right edge, the core
          // between them; the columns grow with the card (cqi) and the wires take
          // the space left, so a wide card has no empty side gutters.
          '@min-[960px]:grid-cols-[clamp(12rem,20cqi,26rem)_clamp(20rem,34cqi,46rem)_clamp(13rem,20cqi,26rem)] @min-[960px]:gap-x-[clamp(2.5rem,5cqi,5.5rem)]'
        )}
        data-testid="exposure-flow"
        data-band={band}
        data-focusing={active ? '' : undefined}
        {...containerProps}
      >
        {layout && !narrow && (
          <svg
            aria-hidden
            className="pointer-events-none absolute inset-0 h-full w-full overflow-visible"
            width={layout.width}
            height={layout.height}
          >
            {wireSources.map((s) => {
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

        {narrow ? (
          <>
            {core}
            {outcomesBlock}
            {stages}
            {sourcesBlock}
          </>
        ) : (
          <>
            {sourcesBlock}
            {core}
            {outcomesBlock}
          </>
        )}

        <FlowTip id={tipId} content={tip} anchor={anchor} />
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

/**
 * The five stages. Each shows its figure with what it measures ("79%
 * scanned"), so a count and a share never read as one unit, and its state as
 * the shared icon set plus words. The stage with the largest gap carries an
 * "Act here" pill instead of a recoloured icon. A phone gets a list (one row
 * per stage, the whole row opens its list); wider cards a row of five.
 */
function StageRow({
  stages,
  focus,
  narrow,
}: {
  stages: Stage[]
  focus: number | null
  narrow: boolean
}) {
  const { t, locale } = useTranslation()
  const stateText = useStageStateText()
  const items = stages.map((s, i) => {
    const name = s.label_key ? t(s.label_key, s.label ?? s.key) : (s.label ?? s.key)
    const value = formatMetric(s.value, s.unit ?? 'count', locale)
    const metric = t(`dashboardKit.flow.stageMetric.${s.key}`, '')
    const state = s.value == null && s.reason_key ? t(s.reason_key) : stateText(s.state)
    const act =
      focus === i
        ? s.flag_key
          ? t(s.flag_key)
          : t('dashboardKit.stage.actHere', 'Act here')
        : null
    const aria = t('dashboardKit.flow.stageAria', '{stage}: {value} {metric}, {state}', {
      stage: name,
      value,
      metric,
      state,
    })
    return { s, i, name, value, metric, state, act, aria }
  })
  if (narrow) {
    return (
      <section
        aria-label={t('dashboardKit.flow.stagesLabel', 'CTEM stage health')}
        data-testid="flow-stages"
      >
        <h3 className="mb-1 text-xs font-medium text-muted-foreground">
          {t('dashboardKit.flow.stagesLabel', 'CTEM stage health')}
        </h3>
        <ol className="grid gap-0.5">
          {items.map((x) => (
            <li key={x.s.key} aria-current={x.act ? 'step' : undefined} data-state={x.s.state}>
              <FlowLink
                to={x.s.drill}
                label={x.aria}
                className="grid min-h-11 grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-2.5 rounded-md px-2 py-1 hover:bg-muted/60 focus-visible:bg-muted/60"
              >
                <StageStateIcon state={x.s.state} className="size-4" />
                <span className="min-w-0">
                  <span className="block truncate text-sm font-medium">{x.name}</span>
                  <span className="flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
                    {x.state}
                    {x.act && <ActHere label={x.act} className="py-0" />}
                  </span>
                </span>
                <span className="text-right">
                  <span
                    className={cn(
                      'block text-base font-semibold tabular-nums leading-tight',
                      x.s.value == null && 'text-muted-foreground'
                    )}
                  >
                    {x.value}
                  </span>
                  {x.metric && (
                    <span className="block text-xs text-muted-foreground">{x.metric}</span>
                  )}
                </span>
              </FlowLink>
            </li>
          ))}
        </ol>
      </section>
    )
  }
  return (
    <ol
      // Five steps in one row from 420 px; three then two rows below (no
      // connecting line then, it would cross the second row).
      className="relative grid w-full max-w-[34rem] grid-cols-3 gap-y-3 before:absolute before:inset-x-[10%] before:top-[11px] before:hidden before:h-px before:bg-border @min-[420px]:grid-cols-5 @min-[420px]:before:block"
      aria-label={t('dashboardKit.flow.stagesLabel', 'CTEM stage health')}
      data-testid="flow-stages"
    >
      {items.map((x) => (
        <li
          key={x.s.key}
          className="relative grid content-start justify-items-center gap-0.5 text-center text-xs"
          aria-current={x.act ? 'step' : undefined}
          data-state={x.s.state}
        >
          <span
            className="grid size-[22px] place-items-center rounded-full bg-card"
            title={x.state}
          >
            <StageStateIcon state={x.s.state} className="size-4" />
          </span>
          <span className="truncate">{x.name}</span>
          <FlowLink
            to={x.s.drill}
            label={x.aria}
            className={cn(
              'inline-grid min-h-11 min-w-11 content-center justify-items-center rounded-md px-1 hover:underline',
              x.s.value == null && 'text-muted-foreground'
            )}
          >
            <span className="text-sm font-semibold tabular-nums leading-tight">{x.value}</span>
            {x.metric && <span className="text-xs text-muted-foreground">{x.metric}</span>}
          </FlowLink>
          {x.act && <ActHere label={x.act} />}
        </li>
      ))}
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
          {row(t('dashboardKit.flow.funnel.actionable', 'Actionable now'), result.actionable)}
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
