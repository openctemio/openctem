'use client'

/** Small pieces shared by the emerging-threat list and detail. */

import { KevBadge } from '@/components/ui/kev-badge'
import type { Locale } from 'date-fns'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { formatEpssScore } from '@/lib/epss'
import { dateFnsLocaleFor } from '@/features/shared/components/activity-timeline'
import { Meter, type MeterTone } from '@/features/shared/components/meter'
import { Clock, List, Zap, type LucideIcon } from 'lucide-react'
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
import type { AlertLevel, AlertState, TimelineEvent } from '../types'

/** date-fns locale of the active language, for relative times. */
export function useDateLocale(): Locale | undefined {
  const { locale } = useTranslation()
  return dateFnsLocaleFor(locale)
}

/**
 * Alert level as a chip (research/247 section 4): immediate is the alert
 * (bolt icon in red), digest is neutral (clock), listed carries no urgency.
 */
const LEVEL_ICON: Record<AlertLevel, LucideIcon> = {
  immediate: Zap,
  digest: Clock,
  listed: List,
}

export function LevelBadge({ level }: { level: AlertLevel }) {
  const { t } = useTranslation()
  return (
    <SignalChip
      slot="alert-level"
      icon={LEVEL_ICON[level] ?? List}
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

/** KEV, ransomware and EPSS of a vulnerability. */
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
  return (
    <div className="flex flex-wrap items-center gap-1">
      {inKev && <KevBadge label={t('emergingThreats.exploit.kev')} />}
      {ransomware && <Badge variant="destructive">{t('emergingThreats.exploit.ransomware')}</Badge>}
      {epss != null && (
        <Badge variant="outline" className="tabular-nums">
          {t('emergingThreats.exploit.epss', undefined, { value: formatEpssScore(epss, 1) })}
        </Badge>
      )}
      {!inKev && !ransomware && epss == null && (
        <span className="text-sm text-muted-foreground">—</span>
      )}
    </div>
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
