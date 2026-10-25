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
 * whose totals are the same sums. On a phone the panel is a stacked list
 * without wires, the summary first.
 */

import { useRef } from 'react'
import { FileUp, GitBranch, Plug, Radar } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { formatCount, formatRelativeTime } from '@/lib/format-metric'
import { cn } from '@/lib/utils'
import { healthNote, originLabel, sourceName } from './exposure-flow-viz'
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
import type { IntakeData, IntakeResult, IntakeSourceRow } from './types'

const ORIGIN_ICON: Record<string, React.ReactNode> = {
  sensor: <Radar className="size-4" aria-hidden />,
  import: <FileUp className="size-4" aria-hidden />,
  connector: <Plug className="size-4" aria-hidden />,
  ci: <GitBranch className="size-4" aria-hidden />,
}

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
    <div className="flex flex-col gap-4">
      <ConnectorPanel data={data} />
      <div className="grid gap-4 xl:grid-cols-2">
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
  const layout = useWireAnchors(ref, [data.sources.length])
  const max = Math.max(1, ...data.sources.map((s) => s.received))
  const lit = (k: string) => !!active && (k === active || k === 'summary' || k === `w:${active}`)
  const activeSource = data.sources.find((s) => `s:${s.id}` === active)
  const shown: IntakeSourceRow = activeSource ?? data.totals

  const tip = ((): FlowTipContent | null => {
    if (!activeSource) return null
    const s = activeSource
    return {
      title: sourceName(t, s),
      rows: [
        [t('dashboardKit.flow.tip.received', 'Received'), n(s.received)],
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
  })()

  return (
    <section className="rounded-lg border" aria-labelledby={`${tipId}-sources`}>
      <header className="flex items-center justify-between gap-3 border-b px-3 py-2">
        <h3 id={`${tipId}-sources`} className="flex items-center gap-2 text-sm font-semibold">
          {t('dashboardKit.intake.sources', 'Sources')}
          <span className="rounded border px-1.5 text-xs font-normal tabular-nums text-muted-foreground">
            {data.sources.length}
          </span>
        </h3>
      </header>
      <div
        ref={ref}
        className="relative grid gap-4 p-3 lg:grid-cols-[minmax(0,1fr)_minmax(14rem,18rem)] lg:gap-x-24"
        {...containerProps}
      >
        {layout && (
          <svg
            aria-hidden
            className="pointer-events-none absolute inset-0 hidden h-full w-full overflow-visible lg:block"
            width={layout.width}
            height={layout.height}
          >
            {data.sources.map((s) => {
              const from = layout.out[`s:${s.id}`]
              const to = layout.in.summary
              if (!from || !to) return null
              const k = `w:s:${s.id}`
              const w = wireStroke(s.health)
              const path = wirePath(from.x + 8, from.y, to.x, to.y)
              return (
                <g key={k} className={dimClass(active, lit(k))} data-wire={s.health}>
                  <path
                    d={path}
                    fill="none"
                    stroke={lit(k) ? 'var(--signal)' : w.stroke}
                    strokeWidth={wireWidth(s.received, max)}
                    strokeDasharray={w.dash}
                    strokeLinecap="round"
                  />
                  {s.health === 'ok' && !reduced && (
                    <path
                      d={path}
                      fill="none"
                      stroke="var(--card, #fff)"
                      strokeOpacity={0.55}
                      strokeWidth={Math.max(1, wireWidth(s.received, max) - 0.5)}
                      strokeDasharray="3 7"
                      className="animate-flow-dash"
                    />
                  )}
                </g>
              )
            })}
          </svg>
        )}

        {/* The summary comes first on a phone. */}
        <div className="order-first lg:order-last lg:self-center">
          <div
            className={cn(
              'relative rounded-lg border bg-muted/40 p-3',
              dimClass(active, lit('summary'))
            )}
            data-k="summary"
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
            <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1 text-sm">
              <dt>{t('dashboardKit.intake.outcome.new', 'New')}</dt>
              <dd className="text-right tabular-nums text-success">+{n(shown.created)}</dd>
              <dt>{t('dashboardKit.intake.outcome.still', 'Still detected')}</dt>
              <dd className="text-right tabular-nums">{n(shown.still_detected)}</dd>
              <dt>{t('dashboardKit.intake.outcome.reopened', 'Reopened')}</dt>
              <dd className="text-right tabular-nums">{n(shown.reopened)}</dd>
              <dt>{t('dashboardKit.intake.outcome.closed', 'Resolved by source')}</dt>
              <dd className="text-right tabular-nums">{n(shown.closed)}</dd>
            </dl>
          </div>
        </div>

        <ul className="grid content-start gap-1">
          {data.sources.map((s) => {
            const k = `s:${s.id}`
            const note = healthNote(t, s, locale)
            const name = sourceName(t, s)
            return (
              <li key={s.id}>
                <FlowLink
                  to={s.drill}
                  className={cn(
                    'grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 rounded-md px-2 py-1.5 hover:bg-muted/60 focus-visible:bg-muted/60',
                    dimClass(active, lit(k))
                  )}
                  {...bind(k)}
                >
                  <span
                    className={cn(
                      'grid size-8 place-items-center rounded-md border text-muted-foreground',
                      s.health === 'stale' && 'border-warning text-warning',
                      s.health === 'failed' && 'border-destructive text-destructive'
                    )}
                    aria-hidden
                  >
                    {ORIGIN_ICON[s.origin] ?? ORIGIN_ICON.sensor}
                  </span>
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-semibold">{name}</span>{' '}
                    <span className="block truncate text-xs text-muted-foreground">
                      {originLabel(t, s.origin)}{' '}
                      <span className="ms-1.5">
                        {tCount(
                          t,
                          'dashboardKit.intake.receiptsCount',
                          '{count} receipts',
                          '{count} receipt',
                          s.receipts,
                          { count: n(s.receipts) }
                        )}
                      </span>
                    </span>
                    {note && (
                      <span
                        className={cn(
                          'block truncate text-xs sm:hidden',
                          s.health === 'stale' ? 'text-warning' : 'text-destructive'
                        )}
                      >
                        {note}
                      </span>
                    )}
                  </span>{' '}
                  <span className="flex items-center gap-2 text-right" data-wire-out={k}>
                    {note && (
                      <span
                        className={cn(
                          'hidden text-xs sm:inline',
                          s.health === 'stale' ? 'text-warning' : 'text-destructive'
                        )}
                      >
                        {note}
                      </span>
                    )}{' '}
                    <span className="text-base font-semibold tabular-nums">{n(s.received)}</span>
                  </span>
                </FlowLink>
              </li>
            )
          })}
        </ul>
        <FlowTip id={tipId} content={tip} anchor={anchor} />
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
  const removed = Math.max(0, noise.received - noise.new)
  const label = (key: (typeof NOISE_PARTS)[number]['key']) =>
    ({
      new: t('dashboardKit.intake.noise.new', 'New or reopened'),
      merged: t('dashboardKit.intake.noise.merged', 'Merged'),
      suppressed: t('dashboardKit.intake.noise.suppressed', 'Suppressed by rules'),
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
        <div
          className="mb-2 flex h-2.5 gap-0.5 overflow-hidden rounded-sm"
          role="img"
          aria-label={t(
            'dashboardKit.intake.noiseBarAria',
            'Received split into new or reopened, merged, suppressed and not stored'
          )}
        >
          {NOISE_PARTS.map((p) =>
            noise[p.key] > 0 ? (
              <span
                key={p.key}
                style={{ flex: noise[p.key], background: p.color }}
                data-part={p.key}
              />
            ) : null
          )}
        </div>
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
