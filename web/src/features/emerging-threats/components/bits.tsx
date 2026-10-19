'use client'

/** Small pieces shared by the emerging-threat list and detail. */

import type { Locale } from 'date-fns'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { formatEpssScore } from '@/lib/epss'
import { dateFnsLocaleFor } from '@/features/shared/components/activity-timeline'
import { Meter, type MeterTone } from '@/features/shared/components/meter'
import { TonePill, type PillTone } from '@/features/shared/components/tone-pill'
import type { AlertLevel, AlertState, TimelineEvent } from '../types'

/** date-fns locale of the active language, for relative times. */
export function useDateLocale(): Locale | undefined {
  const { locale } = useTranslation()
  return dateFnsLocaleFor(locale)
}

const LEVEL_TONE: Record<AlertLevel, PillTone> = {
  immediate: 'destructive',
  digest: 'warning',
  listed: 'muted',
}

export function LevelBadge({ level }: { level: AlertLevel }) {
  const { t } = useTranslation()
  return (
    <TonePill
      tone={LEVEL_TONE[level] ?? 'muted'}
      state={level}
      label={t(`emergingThreats.level.${level}`, level)}
      title={t(`emergingThreats.levelHint.${level}`, '')}
    />
  )
}

const STATE_TONE: Record<AlertState, PillTone> = {
  new: 'info',
  acknowledged: 'info',
  remediating: 'warning',
  not_affected: 'muted',
  resolved: 'success',
}

export function StateBadge({ state }: { state: AlertState }) {
  const { t } = useTranslation()
  return (
    <TonePill
      tone={STATE_TONE[state] ?? 'muted'}
      state={state}
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
      {inKev && <Badge variant="destructive">{t('emergingThreats.exploit.kev')}</Badge>}
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
