'use client'

/** Small pieces shared by the emerging-threat list and detail. */

import Link from '@/components/link'
import { KevBadge } from '@/components/ui/kev-badge'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { formatEpssScore } from '@/lib/epss'
import { Meter, type MeterTone } from '@/features/shared/components/meter'
import { Clock, Crown, Eye, Globe, Zap, type LucideIcon } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { KeyValueList, type KeyValueItem } from '@/features/shared/components/text-layout'
import { SignalChip } from '@/components/ui/signal-chip'
import { StatusLozenge } from '@/components/ui/status-lozenge'
import {
  CheckCircleGlyph,
  DashedCircleGlyph,
  HalfCircleGlyph,
  RingDotGlyph,
  SlashedCircleGlyph,
  type StatusGlyph,
} from '@/components/ui/status-glyphs'
import type { StatusTone } from '@/lib/status-colors'
import type {
  AlertLevel,
  AlertState,
  EmergingThreatSummary,
  EtsBreakdown,
  TimelineEvent,
} from '../types'

/**
 * Alert level as a priority chip (research/247 section 4, research/463 D1):
 * the words say what to do (Act now, This week, Watch); the API values
 * (immediate, digest, listed) name the notification cadence, which the
 * tooltip explains. Act now is the alert tone (bolt icon in red).
 */
const LEVEL_ICON: Record<AlertLevel, LucideIcon> = {
  immediate: Zap,
  digest: Clock,
  listed: Eye,
}

export function LevelBadge({ level }: { level: AlertLevel }) {
  const { t } = useTranslation()
  return (
    <SignalChip
      slot="alert-level"
      icon={LEVEL_ICON[level] ?? Eye}
      tone={level === 'immediate' ? 'alert' : 'neutral'}
      data-level={level}
      title={t(`emergingThreats.levelHint.${level}`, '')}
    >
      {t(`emergingThreats.level.${level}`, level)}
    </SignalChip>
  )
}

/** Alert state on the shared workflow tones (research/247 section 4). */
export const ALERT_STATE_TONE: Record<AlertState, { tone: StatusTone; icon: StatusGlyph }> = {
  new: { tone: 'triage', icon: DashedCircleGlyph },
  acknowledged: { tone: 'open', icon: RingDotGlyph },
  remediating: { tone: 'progress', icon: HalfCircleGlyph },
  resolved: { tone: 'resolved', icon: CheckCircleGlyph },
  not_affected: { tone: 'closed', icon: SlashedCircleGlyph },
}

export function StateBadge({ state }: { state: AlertState }) {
  const { t } = useTranslation()
  const cfg = ALERT_STATE_TONE[state] ?? { tone: 'closed' as const, icon: SlashedCircleGlyph }
  return (
    <StatusLozenge
      tone={cfg.tone}
      icon={cfg.icon}
      value={state}
      label={t(`emergingThreats.state.${state}`, state)}
    />
  )
}

function etsTone(ets: number): MeterTone {
  if (ets >= 75) return 'destructive'
  if (ets >= 50) return 'warning'
  return 'default'
}

/** The score as a number with a thin bar under it. */
export function EtsCell({ ets }: { ets: number }) {
  const { t } = useTranslation()
  return (
    <div className="w-20">
      <span className="text-sm font-semibold tabular-nums">{Math.round(ets)}</span>
      <Meter
        value={ets}
        max={100}
        tone={etsTone(ets)}
        label={t('emergingThreats.ets.meter', undefined, { n: Math.round(ets) })}
        className="mt-1"
      />
    </div>
  )
}

export const ETS_PARTS = ['exploitation', 'severity', 'exposure', 'freshness'] as const

/** The parts of the score as label/value rows (tooltip and drawer). */
export function EtsBreakdownList({ breakdown }: { breakdown: EtsBreakdown }) {
  const { t } = useTranslation()
  const items: KeyValueItem[] = [
    ...ETS_PARTS.map((k) => ({
      key: k,
      label: t(`emergingThreats.breakdown.${k}`),
      value: <span className="tabular-nums">{breakdown[k]}</span>,
    })),
    {
      key: 'confidence',
      label: t('emergingThreats.breakdown.confidence'),
      value: (
        <span className="tabular-nums">
          {t('emergingThreats.breakdown.multiplier', undefined, {
            value: Number(breakdown.confidence.toFixed(2)),
          })}
        </span>
      ),
    },
    {
      key: 'total',
      label: t('emergingThreats.breakdown.total'),
      value: <span className="font-semibold tabular-nums">{breakdown.total}</span>,
    },
  ]
  return <KeyValueList items={items} />
}

/** The score on one line (number and a short meter); hover shows why. */
export function ScoreCell({ ets, breakdown }: { ets: number; breakdown?: EtsBreakdown }) {
  const { t } = useTranslation()
  const n = Math.round(ets)
  const body = (
    <span className="inline-flex items-center gap-2" data-slot="ets-score">
      <span className="w-6 text-sm font-semibold tabular-nums">{n}</span>
      <Meter
        value={ets}
        max={100}
        tone={etsTone(ets)}
        label={t('emergingThreats.ets.meter', undefined, { n })}
        className="w-12"
      />
    </span>
  )
  if (!breakdown) return body
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="cursor-help rounded-sm"
          aria-label={t('emergingThreats.ets.meter', undefined, { n })}
        >
          {body}
        </button>
      </TooltipTrigger>
      <TooltipContent className="w-56">
        <p className="mb-1 font-medium">{t('emergingThreats.score.why')}</p>
        <EtsBreakdownList breakdown={breakdown} />
      </TooltipContent>
    </Tooltip>
  )
}

/**
 * KEV, ransomware and EPSS of a vulnerability (research/463 D5). Known
 * exploited outranks a probability: with KEV the EPSS figure moves to the
 * tooltip; without it the figure shows as "Exploit chance N%".
 */
export function ExploitBadges({
  inKev,
  ransomware,
  epss,
}: {
  inKev: boolean
  ransomware: boolean
  epss: number | null
}) {
  const { t } = useTranslation()
  const epssText = epss != null ? formatEpssScore(epss, 1) : null
  const hint = [
    inKev ? t('emergingThreats.exploit.kevHint') : null,
    epssText ? t('emergingThreats.exploit.epssHint', undefined, { value: epssText }) : null,
  ]
    .filter(Boolean)
    .join(' ')
  if (!inKev && !ransomware && epssText == null) {
    return (
      <span
        className="text-sm text-muted-foreground"
        aria-label={t('emergingThreats.exploit.none')}
      >
        —
      </span>
    )
  }
  return (
    <span className="flex flex-nowrap items-center gap-1" title={hint || undefined}>
      {inKev && <KevBadge label={t('emergingThreats.exploit.kev')} />}
      {ransomware && <Badge variant="destructive">{t('emergingThreats.exploit.ransomware')}</Badge>}
      {!inKev && epssText != null && (
        <Badge variant="outline" className="whitespace-nowrap tabular-nums">
          {t('emergingThreats.exploit.epss', undefined, { value: epssText })}
        </Badge>
      )}
    </span>
  )
}

/** Compact affected-asset tokens: zeros are left out, the tooltip spells all four. */
export function AffectedCell({
  confirmed,
  possible,
  internet,
  critical,
}: {
  confirmed: number
  possible: number
  internet: number
  critical: number
}) {
  const { t } = useTranslation()
  const full = t('emergingThreats.affected.summary', undefined, {
    confirmed,
    possible,
    internet,
    critical,
  })
  return (
    <span
      className="inline-flex items-center gap-3 whitespace-nowrap text-sm tabular-nums"
      title={full}
      aria-label={full}
      data-slot="affected-cell"
    >
      {confirmed > 0 && (
        <span aria-hidden className="font-medium">
          {confirmed}
        </span>
      )}
      {possible > 0 && (
        <span aria-hidden className="text-muted-foreground">
          {/* "+2" beside a confirmed count, "2 possible" on its own. */}
          {confirmed > 0
            ? t('emergingThreats.affected.possibleShort', undefined, { n: possible })
            : t('emergingThreats.affected.possibleOnly', undefined, { n: possible })}
        </span>
      )}
      {internet > 0 && (
        <span aria-hidden className="inline-flex items-center gap-1">
          <Globe className="size-3.5 text-muted-foreground" />
          {internet}
        </span>
      )}
      {critical > 0 && (
        <span aria-hidden className="inline-flex items-center gap-1">
          <Crown className="size-3.5 text-muted-foreground" />
          {critical}
        </span>
      )}
    </span>
  )
}

/** CVE id (link) over the in-scope product, never the id twice (research/463 D4). */
export function ThreatCell({
  alert,
  href,
}: {
  alert: Pick<EmergingThreatSummary, 'vuln_id' | 'product' | 'product_count'>
  href: string
}) {
  const { t } = useTranslation()
  const more = Math.max(0, (alert.product_count ?? 0) - 1)
  return (
    <div className="min-w-0 max-w-xs">
      <Link
        href={href}
        className="font-mono text-sm font-medium hover:underline"
        onClick={(e) => e.stopPropagation()}
      >
        {alert.vuln_id}
      </Link>
      {alert.product ? (
        <p className="flex min-w-0 items-center gap-1.5 text-sm text-muted-foreground">
          <span className="truncate">{alert.product}</span>
          {more > 0 && (
            <span
              className="shrink-0 tabular-nums"
              title={t('emergingThreats.threat.moreProductsHint', undefined, { n: more })}
            >
              {t('emergingThreats.threat.moreProducts', undefined, { n: more })}
            </span>
          )}
        </p>
      ) : null}
    </div>
  )
}

/** The last change as one short phrase and a relative time; the detail is the tooltip. */
export function LastChangeCell({ kind, at }: { kind: string; at: string | null }) {
  const { t } = useTranslation()
  const long = useEventKindLabel()
  if (!kind && !at) return <span className="text-sm text-muted-foreground">—</span>
  const short = kind
    ? KNOWN_KINDS.includes(kind)
      ? t(`emergingThreats.eventShort.${kind}`)
      : kind.replace(/_/g, ' ')
    : ''
  return (
    <span
      className="inline-flex items-baseline gap-2 whitespace-nowrap text-sm"
      title={kind ? long(kind) : undefined}
    >
      {short && <span>{short}</span>}
      <RelativeTime date={at} className="text-muted-foreground" />
    </span>
  )
}

const KNOWN_KINDS = [
  'published',
  'ranges_added',
  'ranges_widened',
  'severity_up',
  'kev_added',
  'epss_crossed',
  'rejected',
]

const str = (v: unknown): string | null =>
  typeof v === 'string' && v ? v : typeof v === 'number' ? String(v) : null

/** The translated name of an event kind; an unknown kind shows as it is. */
export function useEventKindLabel() {
  const { t } = useTranslation()
  return (kind: string): string =>
    KNOWN_KINDS.includes(kind) ? t(`emergingThreats.event.${kind}`) : kind.replace(/_/g, ' ')
}

/** A short readable line for an event's `detail`, or null when there is nothing to add. */
export function useEventDetail() {
  const { t } = useTranslation()
  return (ev: TimelineEvent): string | null => {
    const d = ev.detail ?? {}
    switch (ev.kind) {
      case 'severity_up': {
        const from = str(d.from)
        const to = str(d.to)
        if (from && to) return t('emergingThreats.eventDetail.severity', undefined, { from, to })
        return to ?? null
      }
      case 'epss_crossed': {
        const v = typeof d.epss === 'number' ? d.epss : typeof d.value === 'number' ? d.value : null
        return v == null
          ? null
          : t('emergingThreats.eventDetail.epss', undefined, { value: formatEpssScore(v, 1) })
      }
      case 'kev_added': {
        const date = str(d.date_added) ?? str(d.kev_date_added)
        return date ? t('emergingThreats.eventDetail.kev', undefined, { date }) : null
      }
      case 'published':
      case 'ranges_added': {
        const n = typeof d.products === 'number' ? d.products : null
        return n ? t('emergingThreats.eventDetail.products', undefined, { count: String(n) }) : null
      }
      case 'ranges_widened': {
        const n = typeof d.products_added === 'number' ? d.products_added : 0
        return n > 0
          ? t('emergingThreats.eventDetail.productsAdded', undefined, { count: String(n) })
          : t('emergingThreats.eventDetail.moreRanges')
      }
      default:
        return null
    }
  }
}
