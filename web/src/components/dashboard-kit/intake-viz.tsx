'use client'

/**
 * Intake and noise reduction (metric ingest.intake; api
 * docs/architecture/dashboards.md, "Exposure flow and intake"): every source
 * with what it sent in the period and its health, wired into one summary;
 * the noise bar (received split into new or reopened, merged into findings
 * that exist, suppressed by an approved rule, not stored); the false
 * positives of the period; and the same figures per source as a table.
 *
 * Every figure opens the receipt list with the same source and period,
 * whose totals are the same sums. The layout follows the widget's own width
 * (container queries): from INTAKE_SIDE (560 px) the source rows keep a
 * fixed reading width at the left (each figure stays beside its name), the
 * summary sits at the right edge and the curves stretch across everything
 * between; below, a stacked list without curves. Sources are the shared
 * ranked rows (RankedBars, source-view): by tool or by instance with its
 * tools under its name, discovery tools by the assets they found, sources
 * with nothing folded into one line.
 */

import { useMemo, useRef } from 'react'
import { FileUp, GitBranch, Plug, Radar } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { KeyValueList } from '@/features/shared/components/text-layout'
import { formatCount, formatRelativeTime } from '@/lib/format-metric'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import {
  FRAME_INSET,
  FlowLink,
  FlowTip,
  tCount,
  dimClass,
  focusGlow,
  useElementWidth,
  useFlowFocus,
  useWireAnchors,
  wirePath,
  wireStroke,
  wireWidth,
  type FlowTipContent,
} from './flow-parts'
import { RankedBars } from './ranked-bars'
import {
  SourceViewSwitchers,
  groupByInstance,
  sourceName,
  sourceRankRows,
  sourceViewFor,
  useSourceView,
} from './source-view'
import { StackedBar } from './stacked-bar'
import { ChartOrTable, usePrefersReducedMotion } from './viz-parts'
import type { IntakeData, IntakeResult, IntakeSourceRow } from './types'

const ORIGIN_ICON: Record<string, React.ReactNode> = {
  sensor: <Radar className="size-4" aria-hidden />,
  import: <FileUp className="size-4" aria-hidden />,
  connector: <Plug className="size-4" aria-hidden />,
  ci: <GitBranch className="size-4" aria-hidden />,
}

/** Source rows with a value before "Show all". */
const MAX_ROWS = 6

/**
 * Panel width (px) from which the sources and the summary sit side by side:
 * the rows at their reading width (20 rem), at least 2.5 rem of curves and
 * the summary (13 rem) fit from here, so a full-width card in a 1024 px
 * window already joins each row to the summary. The container classes below
 * use the same number.
 */
export const INTAKE_SIDE = 560

/** The dashed frame of the sources and the summary once they sit side by side. */
const INTAKE_FRAME =
  '@min-[560px]:rounded-lg @min-[560px]:border @min-[560px]:border-dashed @min-[560px]:border-border-strong @min-[560px]:p-1.5'

/** Noise bar segments, in fixed order, with their chart colour. */
export const NOISE_PARTS = [
  { key: 'new', color: 'var(--foreground)' },
  { key: 'merged', color: 'var(--viz-cat-1)' },
  { key: 'suppressed', color: 'var(--viz-cat-3)' },
  { key: 'not_stored', color: 'var(--warning)' },
] as const

export function IntakeViz({ result }: { result: IntakeResult }) {
  const { t, locale } = useTranslation()
  const d = result.intake
  const summary = t(
    'dashboardKit.intake.summary',
    'Intake: {received} findings received from {sources} sources, {new} new or reopened.',
    {
      received: formatCount(d.totals.received, locale),
      sources: d.sources.length,
      new: formatCount(d.noise.new, locale),
    }
  )
  return (
    <ChartOrTable
      chart={<IntakePanel data={d} />}
      table={<SourceTable data={d} />}
      summary={summary}
    />
  )
}

function IntakePanel({ data }: { data: IntakeData }) {
  const { t, locale } = useTranslation()
  const n = (v: number) => formatCount(v, locale)
  return (
    <div className="@container flex flex-col gap-4">
      <ConnectorPanel data={data} />
      <div className="grid gap-4 @min-[1100px]:grid-cols-2">
        <NoiseReduction data={data} />
        <section className="min-w-0 rounded-lg border p-3" aria-labelledby="intake-per-source">
          <h3 id="intake-per-source" className="mb-2 text-sm font-semibold">
            {t('dashboardKit.intake.perSource', 'Per source')}
          </h3>
          <SourceTable data={data} />
          <p className="mt-2 text-xs text-muted-foreground">
            {t(
              'dashboardKit.intake.orgFigures',
              'Organization figures, from the import and run receipts'
            )}
          </p>
        </section>
      </div>
      <p className="sr-only">
        {t('dashboardKit.intake.totalsSr', '{received} received, {receipts} receipts', {
          received: n(data.totals.received),
          receipts: n(data.totals.receipts),
        })}
      </p>
    </div>
  )
}

function ConnectorPanel({ data }: { data: IntakeData }) {
  const { t, locale } = useTranslation()
  const n = (v: number) => formatCount(v, locale)
  const ref = useRef<HTMLDivElement>(null)
  const reduced = usePrefersReducedMotion()
  const { active, anchor, tipId, bind, containerProps } = useFlowFocus(ref)
  const band = useElementWidth(ref) >= INTAKE_SIDE ? 'side' : 'narrow'
  const [measure, group, setMeasure, setGroup] = useSourceView()
  const { m, g, hasAssets, hasInstances } = sourceViewFor(data.sources, measure, group)
  const instances = useMemo(() => groupByInstance(t, data.sources), [t, data.sources])
  const rows = useMemo(
    () =>
      sourceRankRows(t, locale, { sources: data.sources, instances, m, g }).map((r) => {
        const s = data.sources.find((x) => `s:${x.id}` === r.key)
        const kind = s?.origin ?? instances.find((x) => `i:${x.key}` === r.key)?.instance.kind
        return { ...r, icon: ORIGIN_ICON[kind ?? 'sensor'] ?? ORIGIN_ICON.sensor }
      }),
    [t, locale, data.sources, instances, m, g]
  )
  const layout = useWireAnchors(ref, `${band}:${m}:${g}:${rows.length}`)
  const max = Math.max(1, ...rows.map((r) => r.value))
  const periodLabel = t('dashboardKit.flow.period', '{days} days', { days: data.days })
  const lit = (k: string) => !!active && (k === active || k === 'summary' || k === `w:${active}`)
  const activeSource = data.sources.find((s) => `s:${s.id}` === active)
  const activeInstance = instances.find((x) => `i:${x.key}` === active)
  const shown: IntakeSourceRow = activeSource ?? data.totals

  const tip = ((): FlowTipContent | null => {
    if (activeInstance) {
      const gr = activeInstance
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
    if (!activeSource) return null
    const s = activeSource
    const rowsOut: Array<[string, string]> = [
      [t('dashboardKit.flow.tip.received', 'Received'), n(s.received)],
    ]
    if ((s.assets ?? 0) > 0) {
      rowsOut.push([
        t('dashboardKit.flow.tip.assets', 'Assets discovered or updated'),
        n(s.assets ?? 0),
      ])
    }
    rowsOut.push(
      [t('dashboardKit.flow.tip.receipts', 'Receipts'), n(s.receipts)],
      [
        t('dashboardKit.flow.tip.lastReceipt', 'Last receipt'),
        formatRelativeTime(s.last_at, locale),
      ]
    )
    return {
      title: sourceName(t, s),
      rows: rowsOut,
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
  })()

  return (
    <section className="rounded-lg border" aria-labelledby={`${tipId}-sources`}>
      <header className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 border-b px-3 py-2">
        <h3 id={`${tipId}-sources`} className="flex items-center gap-2 text-sm font-semibold">
          {t('dashboardKit.intake.sources', 'Sources')}
          <span className="rounded border px-1.5 text-xs font-normal tabular-nums text-muted-foreground">
            {data.sources.length}
          </span>
        </h3>
        <SourceViewSwitchers
          m={m}
          g={g}
          hasAssets={hasAssets}
          hasInstances={hasInstances}
          setMeasure={setMeasure}
          setGroup={setGroup}
        />
      </header>
      <div className="@container">
        <div
          ref={ref}
          className={cn(
            'relative grid gap-4 p-3',
            // Side by side: the source rows at a fixed reading width (each row's
            // figure stays beside its name whatever the card), the summary at
            // the right edge, and the curves take every pixel between.
            '@min-[560px]:grid-cols-[20rem_minmax(2.5rem,1fr)_clamp(13rem,22cqi,18rem)] @min-[560px]:gap-x-0'
          )}
          data-band={band}
          {...containerProps}
        >
          {layout && band !== 'narrow' && (
            <svg
              aria-hidden
              className="pointer-events-none absolute inset-0 h-full w-full overflow-visible"
              width={layout.width}
              height={layout.height}
            >
              {rows.map((r) => {
                const from = layout.out[r.key]
                const to = layout.in.summary
                if (!from || !to) return null
                const k = `w:${r.key}`
                const w = wireStroke(r.health ?? 'ok')
                const path = wirePath(from.x + FRAME_INSET, from.y, to.x, to.y)
                const on = lit(k)
                return (
                  <g
                    key={k}
                    className={dimClass(active, on)}
                    data-wire={r.health ?? 'ok'}
                    data-wire-key={k}
                  >
                    <path
                      d={path}
                      fill="none"
                      stroke={on ? 'var(--signal)' : w.stroke}
                      style={on ? { filter: focusGlow('var(--signal)') } : undefined}
                      strokeWidth={wireWidth(r.value, max)}
                      strokeDasharray={w.dash}
                      strokeLinecap="round"
                    />
                    {(r.health ?? 'ok') === 'ok' && !reduced && (
                      <path
                        d={path}
                        fill="none"
                        stroke="var(--card, #fff)"
                        strokeOpacity={0.55}
                        strokeWidth={Math.max(1, wireWidth(r.value, max) - 0.5)}
                        strokeDasharray="3 7"
                        className="animate-flow-dash"
                      />
                    )}
                  </g>
                )
              })}
            </svg>
          )}

          <div
            className={cn('min-w-0 @min-[560px]:self-start', INTAKE_FRAME)}
            data-testid="intake-sources"
          >
            <RankedBars
              rows={rows}
              limit={MAX_ROWS}
              label={t('dashboardKit.intake.sources', 'Sources')}
              resetKey={`${m}:${g}`}
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
                'data-wire-out': r.key,
                ...bind(r.key),
              })}
            />
          </div>
          {/* The summary: at the right edge side by side, below the sources on a phone. */}
          <div className="@min-[560px]:col-start-3 @min-[560px]:self-center">
            <div
              className={cn(
                'relative rounded-lg border bg-muted/40 p-3 @min-[560px]:border-dashed @min-[560px]:border-border-strong @min-[560px]:bg-transparent',
                dimClass(active, lit('summary'))
              )}
              data-k="summary"
              data-testid="intake-summary"
            >
              <span
                className="absolute -left-px top-1/2 size-px"
                data-wire-in="summary"
                aria-hidden
              />
              <p className="text-xs text-muted-foreground">
                {activeSource
                  ? sourceName(t, activeSource)
                  : t('dashboardKit.intake.allFindings', 'All findings')}
              </p>
              <FlowLink
                to={activeSource ? activeSource.drill : data.drill}
                label={t('dashboardKit.intake.receivedAria', '{count} findings received', {
                  count: n(shown.received),
                })}
                className="block w-fit text-3xl font-semibold leading-tight tabular-nums hover:underline"
              >
                {n(shown.received)}
              </FlowLink>
              <p className="mb-2 text-xs text-muted-foreground">
                {activeSource
                  ? tCount(
                      t,
                      'dashboardKit.intake.fromReceipts',
                      'from {count} receipts',
                      'from {count} receipt',
                      activeSource.receipts,
                      { count: n(activeSource.receipts) }
                    )
                  : tCount(
                      t,
                      'dashboardKit.intake.fromSources',
                      'received from {count} sources',
                      'received from {count} source',
                      data.sources.length,
                      { count: data.sources.length }
                    )}
              </p>
              <KeyValueList
                // Short figures: label and value side by side at every width.
                className="grid-cols-[minmax(6rem,max-content)_minmax(0,1fr)] gap-y-1 sm:gap-y-1"
                items={[
                  {
                    key: 'new',
                    label: t('dashboardKit.intake.outcome.new', 'New'),
                    value: <span className="tabular-nums text-success">+{n(shown.created)}</span>,
                  },
                  {
                    key: 'still',
                    label: t('dashboardKit.intake.outcome.still', 'Still detected'),
                    value: <span className="tabular-nums">{n(shown.still_detected)}</span>,
                  },
                  {
                    key: 'reopened',
                    label: t('dashboardKit.intake.outcome.reopened', 'Reopened'),
                    value: <span className="tabular-nums">{n(shown.reopened)}</span>,
                  },
                  {
                    key: 'closed',
                    label: t('dashboardKit.intake.outcome.closed', 'Resolved by source'),
                    value: <span className="tabular-nums">{n(shown.closed)}</span>,
                  },
                ]}
              />
            </div>
          </div>

          <FlowTip id={tipId} content={tip} anchor={anchor} />
        </div>
      </div>
      <footer className="flex flex-wrap justify-between gap-x-4 gap-y-1 border-t px-3 py-2 text-xs text-muted-foreground">
        <span>
          {data.totals.last_at
            ? t('dashboardKit.intake.lastReceipt', 'Last receipt {when}', {
                when: formatRelativeTime(data.totals.last_at, locale),
              })
            : null}
          {data.totals.last_status === 'failed' && (
            <span className="ms-1.5 text-destructive">
              {t('dashboardKit.intake.failedStatus', 'failed')}
            </span>
          )}
        </span>
        <span className="flex gap-3">
          {data.failing > 0 && (
            <span className="text-destructive">
              {t('dashboardKit.intake.failing', '{count} failing', { count: data.failing })}
            </span>
          )}
          {data.stale > 0 && (
            <span className="text-warning">
              {t('dashboardKit.intake.stale', '{count} stale', { count: data.stale })}
            </span>
          )}
          <FlowLink to={data.drill} className="text-signal-text hover:underline">
            {t('dashboardKit.intake.allReceipts', 'All receipts')}
          </FlowLink>
        </span>
      </footer>
    </section>
  )
}

function NoiseReduction({ data }: { data: IntakeData }) {
  const { t, locale } = useTranslation()
  const n = (v: number) => formatCount(v, locale)
  const noise = data.noise
  // New or reopened is the receipt list's New plus Reopened. Suppressed is
  // the part of it an approved rule closed on arrival, so the bar draws it
  // inside New, and the removed noise adds it back (it was never opened).
  const removed = Math.max(0, noise.received - noise.new) + noise.suppressed
  const segment = (key: (typeof NOISE_PARTS)[number]['key']) =>
    key === 'new' ? Math.max(0, noise.new - noise.suppressed) : noise[key]
  const label = (key: (typeof NOISE_PARTS)[number]['key']) =>
    ({
      new: t('dashboardKit.intake.noise.new', 'New or reopened'),
      merged: t('dashboardKit.intake.noise.merged', 'Merged'),
      suppressed: t('dashboardKit.intake.noise.suppressed', 'of which suppressed by rules'),
      not_stored: t('dashboardKit.intake.noise.notStored', 'Not stored'),
    })[key]
  const days = data.days
  return (
    <section className="min-w-0 rounded-lg border p-3" aria-labelledby="intake-noise">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h3 id="intake-noise" className="text-sm font-semibold">
          {t('dashboardKit.intake.noiseTitle', 'Noise reduction')}
        </h3>
        <span className="text-xs text-muted-foreground">
          {t('dashboardKit.intake.pastDays', 'Past {days} days', { days })}
        </span>
      </div>
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <p className="flex flex-wrap items-baseline gap-x-2">
          <span className="text-xs text-muted-foreground">
            {t('dashboardKit.flow.funnel.received', 'Received')}
          </span>
          <FlowLink
            to={data.drill}
            className="text-3xl font-semibold leading-none tabular-nums hover:underline"
          >
            {n(noise.received)}
          </FlowLink>
          <span className="text-muted-foreground" aria-hidden>
            →
          </span>
          <span className="text-xs text-muted-foreground">
            {t('dashboardKit.intake.noise.new', 'New or reopened')}
          </span>
          <FlowLink
            to={data.drill}
            className="text-3xl font-semibold leading-none tabular-nums hover:underline"
          >
            {n(noise.new)}
          </FlowLink>
        </p>
        <span className="text-xs font-medium text-success">
          {t('dashboardKit.intake.noiseRemoved', '{count} noise removed', { count: n(removed) })}
        </span>
      </div>
      {noise.received > 0 && (
        <StackedBar
          className="mb-2 h-2.5 rounded-sm"
          ariaLabel={t(
            'dashboardKit.intake.noiseBarAria',
            'Received split into new or reopened (some suppressed by rules), merged and not stored'
          )}
          parts={NOISE_PARTS.map((p) => ({ key: p.key, value: segment(p.key), color: p.color }))}
        />
      )}
      <ul className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {NOISE_PARTS.map((p) => (
          <li key={p.key} className="inline-flex items-center gap-1.5">
            <span className="size-2.5 rounded-sm" style={{ background: p.color }} aria-hidden />
            <span className="text-muted-foreground">{label(p.key)}</span>
            <FlowLink
              to={data.drill}
              label={`${label(p.key)}: ${n(noise[p.key])}`}
              className="font-semibold tabular-nums hover:underline"
            >
              {n(noise[p.key])}
            </FlowLink>
          </li>
        ))}
      </ul>
      <div className="flex items-center justify-between gap-3 rounded-md border px-3 py-2 opacity-80">
        <span className="min-w-0 text-sm text-muted-foreground">
          <span className="line-through">
            {t('dashboardKit.intake.fpRow', 'Closed as false positive')}
          </span>
          <span className="ms-2 rounded border px-1.5 py-0.5 text-xs no-underline">
            {t('dashboardKit.intake.fpChip', 'False positive, approved')}
          </span>
        </span>
        <FlowLink
          to={data.false_positive.drill}
          label={t('dashboardKit.intake.fpAria', '{count} findings closed as false positive', {
            count: n(data.false_positive.value),
          })}
          className="text-base font-semibold tabular-nums hover:underline"
        >
          {n(data.false_positive.value)}
        </FlowLink>
      </div>
    </section>
  )
}

/** The figures per source; every number opens that source's receipts. */
export function SourceTable({ data }: { data: IntakeData }) {
  const { t, locale } = useTranslation()
  const n = (v: number) => formatCount(v, locale)
  const cols: Array<{ key: string; label: string; value: (s: IntakeSourceRow) => number }> = [
    {
      key: 'received',
      label: t('dashboardKit.intake.col.received', 'Received'),
      value: (s) => s.received,
    },
    { key: 'new', label: t('dashboardKit.intake.col.new', 'New'), value: (s) => s.created },
    {
      key: 'still',
      label: t('dashboardKit.intake.col.still', 'Still detected'),
      value: (s) => s.still_detected,
    },
    {
      key: 'closed',
      label: t('dashboardKit.intake.col.closed', 'Resolved'),
      value: (s) => s.closed,
    },
  ]
  // Discovery tools report assets, not findings: give them their own column.
  if (data.sources.some((s) => (s.assets ?? 0) > 0)) {
    cols.push({
      key: 'assets',
      label: t('dashboardKit.intake.col.assets', 'Assets'),
      value: (s) => s.assets ?? 0,
    })
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[32rem] text-sm">
        <thead>
          <tr className="border-b text-xs text-muted-foreground">
            <th scope="col" className="py-1.5 pe-3 text-left font-medium">
              {t('dashboardKit.intake.col.source', 'Source')}
            </th>
            {cols.map((c) => (
              <th key={c.key} scope="col" className="px-2 py-1.5 text-right font-medium">
                {c.label}
              </th>
            ))}
            <th scope="col" className="ps-2 py-1.5 text-right font-medium">
              {t('dashboardKit.intake.col.last', 'Last')}
            </th>
          </tr>
        </thead>
        <tbody>
          {data.sources.map((s) => (
            <tr key={s.id} className="border-b last:border-0">
              <th scope="row" className="max-w-[12rem] truncate py-1.5 pe-3 text-left font-normal">
                {sourceName(t, s)}
              </th>
              {cols.map((c) => (
                <td key={c.key} className="px-2 py-1.5 text-right tabular-nums">
                  <FlowLink to={s.drill} className="hover:underline">
                    {n(c.value(s))}
                  </FlowLink>
                </td>
              ))}
              <td
                className={cn(
                  'ps-2 py-1.5 text-right text-xs',
                  s.health === 'failed'
                    ? 'text-destructive'
                    : s.health === 'stale'
                      ? 'text-warning'
                      : 'text-muted-foreground'
                )}
              >
                {s.health === 'failed'
                  ? t('dashboardKit.intake.failedStatus', 'failed')
                  : formatRelativeTime(s.last_at, locale, new Date(), 'narrow')}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
