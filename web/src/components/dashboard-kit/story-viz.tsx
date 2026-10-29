'use client'

/**
 * The dashboard's story widgets (api docs/architecture/dashboards.md, "Story
 * widgets"): the KPI strip, the levers and the weekly brief. Every figure
 * comes from the dashboard's snapshot; every number that has a list opens
 * it. No accent stripes: state is carried by the number's own colour, a chip
 * or the text.
 */

import Link from '@/components/link'
import { SignalChip } from '@/components/ui/signal-chip'
import { useTranslation } from '@/context/i18n-provider'
import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'
import { formatCount, formatMetric } from '@/lib/format-metric'
import { cn } from '@/lib/utils'
import { changeOf } from './compare'
import { DeltaText } from './viz-parts'
import type { BriefChip, BriefResult, KpisResult, LeverRow, LeversResult } from './types'

/** Five key figures in one divided strip (the shared metric strip). */
export function KpiStripViz({ result }: { result: KpisResult }) {
  const { t, locale } = useTranslation()
  const items: MetricStripItem[] = result.tiles.map((tile) => {
    const label = t(`dashboardKit.kpi.${tile.key}`, tile.key)
    const reason = tile.reason_key ? t(tile.reason_key) : undefined
    if (!tile.measured) {
      return {
        key: tile.key,
        label,
        value: t('dashboardKit.kpi.notMeasured', 'Not measured'),
        description: reason,
        detail: reason,
      }
    }
    return {
      key: tile.key,
      label,
      value: formatMetric(tile.value, tile.unit, locale),
      description: t(`dashboardKit.kpi.${tile.key}Definition`, ''),
      href: tile.href ?? undefined,
      detail: (
        <DeltaText
          delta={changeOf(tile.value, tile.previous)}
          unit={tile.unit}
          polarity={tile.polarity}
          previous={tile.previous}
        />
      ),
    }
  })
  return <MetricStrip items={items} className="border-0 bg-transparent" />
}

/** The plain-words sentence of a lever (shared by the levers and the brief). */
export function useLeverSentence() {
  const { t, locale } = useTranslation()
  return (l: LeverRow): string => {
    const before = formatMetric(l.effect.before, l.effect.unit, locale)
    const after = formatMetric(l.effect.after, l.effect.unit, locale)
    switch (l.kind) {
      case 'kev_open':
        return l.effect.metric === 'intel.kev_open'
          ? t(
              'dashboardKit.levers.kevOpenNoPriority',
              '{count, plural, one {# known-exploited finding is} other {# known-exploited findings are}} open; fixing them takes KEV open from {before} to {after}.',
              { count: l.count, before, after }
            )
          : t(
              'dashboardKit.levers.kevOpen',
              '{count, plural, one {# known-exploited finding is} other {# known-exploited findings are}} open; fixing them cuts P0–P1 open from {before} to {after}.',
              { count: l.count, before, after }
            )
      case 'sla_breached':
        return t(
          'dashboardKit.levers.slaBreached',
          '{count, plural, one {# P0–P1 finding is} other {# P0–P1 findings are}} past the SLA; fixing them lifts within SLA from {before} to {after}.',
          { count: l.count, before, after }
        )
      case 'one_fix':
        return t(
          'dashboardKit.levers.oneFix',
          '{title} closes {count, plural, one {# finding} other {# findings}} on {assets, plural, one {# asset} other {# assets}}; P0–P1 open goes from {before} to {after}.',
          { title: l.title ?? '', count: l.count, assets: l.assets ?? 0, before, after }
        )
      case 'blind_spot':
        return t(
          'dashboardKit.levers.blindSpot',
          '{count, plural, one {# tracked asset has} other {# tracked assets have}} no successful scan in the coverage window; covering them takes coverage from {before} to {after}.',
          { count: l.count, before, after }
        )
      default:
        return ''
    }
  }
}

/** The actions that would most reduce exposure, each with its exact effect. */
export function LeversViz({ result }: { result: LeversResult }) {
  const { t, locale } = useTranslation()
  const sentence = useLeverSentence()
  if (result.levers.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {t(
          'dashboardKit.levers.none',
          'Nothing stands out: no known-exploited, past-SLA or single-fix work in this scope.'
        )}
      </p>
    )
  }
  return (
    <ol
      className={cn(
        'grid divide-y sm:divide-x sm:divide-y-0',
        result.levers.length === 1 && 'sm:grid-cols-1',
        result.levers.length === 2 && 'sm:grid-cols-2',
        result.levers.length >= 3 && 'sm:grid-cols-3'
      )}
      aria-label={t('dashboardKit.levers.label', 'Levers')}
    >
      {result.levers.map((l, i) => {
        const before = formatMetric(l.effect.before, l.effect.unit, locale)
        const after = formatMetric(l.effect.after, l.effect.unit, locale)
        return (
          <li
            key={`${l.kind}-${i}`}
            data-slot="lever"
            className="flex min-w-0 flex-col gap-1 py-3 first:pt-0 last:pb-0 sm:px-4 sm:py-0 sm:first:ps-0 sm:last:pe-0"
          >
            <span className="text-xs text-muted-foreground">
              {t(`dashboardKit.levers.kind.${l.kind}`, l.kind)}
            </span>
            <span
              className="text-kpi tabular-nums"
              aria-label={t('dashboardKit.levers.effect', 'From {before} to {after}', {
                before,
                after,
              })}
            >
              {before} → {after}
            </span>
            <p className="text-sm leading-relaxed">{sentence(l)}</p>
            {l.href && (
              <Link
                href={l.href}
                className="mt-auto text-xs font-medium text-primary hover:underline"
              >
                {t('dashboardKit.levers.open', 'Open the list ({count})', {
                  count: formatCount(l.count, locale),
                })}
              </Link>
            )}
          </li>
        )
      })}
    </ol>
  )
}

function Chip({ chip }: { chip: BriefChip }) {
  const { t, locale } = useTranslation()
  const body = (
    <SignalChip>
      {t(`dashboardKit.brief.chip.${chip.key}`, chip.key)} {formatCount(chip.value, locale)}
    </SignalChip>
  )
  return chip.href ? (
    <Link href={chip.href} className="rounded-md hover:underline">
      {body}
    </Link>
  ) : (
    body
  )
}

/** The weekly brief: deterministic sentences, each followed by its figures. */
export function BriefViz({ result }: { result: BriefResult }) {
  const { t } = useTranslation()
  const sentence = useLeverSentence()
  const n = (key: string, item: BriefResult['items'][number]) =>
    item.chips.find((c) => c.key === key)?.value ?? 0
  const items = result.items.length > 0 ? result.items : [{ kind: 'quiet' as const, chips: [] }]
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <ol className="flex list-decimal flex-col gap-2.5 ps-5 text-sm leading-relaxed">
        {items.map((it, i) => {
          let text = ''
          switch (it.kind) {
            case 'change':
              text = t(
                `dashboardKit.brief.change.${it.variant ?? 'flat'}`,
                'Open exposure this week: {opened} new, {fixed} fixed.',
                { opened: n('opened', it), fixed: n('fixed', it) }
              )
              break
            case 'lever':
              text = it.lever
                ? t('dashboardKit.brief.lever', 'Biggest lever: {sentence}', {
                    sentence: sentence(it.lever),
                  })
                : ''
              break
            case 'sla_due':
              text = t(
                'dashboardKit.brief.slaDue',
                '{due, plural, one {# P0–P2 finding reaches} other {# P0–P2 findings reach}} the SLA soon, and {past} are past it.',
                { due: n('due_soon', it), past: n('past_sla', it) }
              )
              break
            case 'kev':
              text = t(
                'dashboardKit.brief.kev',
                '{count, plural, one {# known-exploited finding is} other {# known-exploited findings are}} open.',
                { count: n('kev_open', it) }
              )
              break
            default:
              text = t(
                'dashboardKit.brief.quiet',
                'Nothing changed this week that needs attention.'
              )
          }
          return (
            <li key={`${it.kind}-${i}`} data-slot="brief-item">
              <span>{text}</span>
              {it.chips.length > 0 && (
                <span className="ms-1 inline-flex flex-wrap gap-1.5 align-middle">
                  {it.chips.map((c) => (
                    <Chip key={c.key} chip={c} />
                  ))}
                </span>
              )}
            </li>
          )
        })}
      </ol>
      <p className="mt-auto text-xs text-muted-foreground">
        {t(
          'dashboardKit.brief.footer',
          'The last 7 days, built from this dashboard’s snapshot with fixed sentences; no AI involved.'
        )}
      </p>
    </div>
  )
}
