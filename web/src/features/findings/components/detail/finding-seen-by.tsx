'use client'

/**
 * The finding page's "Seen by" section: every source that reported this
 * finding (a scan, a sensor task or report, an upload, a CI run, a
 * connector, the platform), with its tool, first and last seen and how
 * many runs or uploads saw it, linked to the last run and to the list of
 * everything that source reported.
 *
 * Read: GET /api/v1/findings/{id}/sightings. The API answers 404 for a
 * finding outside the caller's data scope (the section hides, no oracle)
 * and leaves out the sensor without sensors:read. A finding a person added
 * has no sources, and the section is absent.
 */

import { type ReactNode } from 'react'
import { Radar } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { useSettleSignal } from '@/features/shared/components/settle-group'
import { ListItem } from '@/features/shared/components/text-layout'
import {
  seenByFindingsHref,
  useFindingSightings,
  type FindingSighting,
} from '../../api/receipts-api'
import { sightingSource } from '../../api/source-retirement-api'
import { RetireSourceButton } from '../source-retirement'
import { SectionLoadError, isLoadFailure } from './section-load-error'

type T = ReturnType<typeof useTranslation>['t']

/** The label of a sighting channel. */
export function sightingChannelLabel(t: T, channel?: string): string {
  switch (channel) {
    case 'scan':
      return t('findings.seenBy.channel.scan', 'Scan')
    case 'task':
      return t('findings.seenBy.channel.task', 'Sensor task')
    case 'sensor':
      return t('findings.seenBy.channel.sensor', 'Sensor report')
    case 'upload':
      return t('findings.seenBy.channel.upload', 'Upload')
    case 'ci':
      return t('findings.seenBy.channel.ci', 'CI run')
    case 'connector':
      return t('findings.seenBy.channel.connector', 'Connector')
    case 'platform':
      return t('findings.seenBy.channel.platform', 'Platform match')
    default:
      return t('findings.seenBy.channel.unknown', 'Earlier source')
  }
}

const linkClass = 'underline-offset-2 hover:underline'

function SightingRow({ s }: { s: FindingSighting }) {
  const { t } = useTranslation()
  // The title names the source: the scan, the sensor, the sender, or the channel.
  let title: ReactNode = sightingChannelLabel(t, s.channel)
  if (s.scan?.id) {
    title = (
      <Link href={seenByFindingsHref('seen_by_scan_id', s.scan.id)} className={linkClass}>
        {s.scan.name || t('findings.seenBy.scan', 'Scan')}
      </Link>
    )
  } else if (s.sender && s.sender !== 'platform') {
    title = (
      <span>
        {sightingChannelLabel(t, s.channel)}{' '}
        <span className="font-mono text-meta" dir="auto">
          {s.sender}
        </span>
      </span>
    )
  }
  const meta: ReactNode[] = []
  const source = sightingSource(s)
  if (s.tool) {
    meta.push(
      <Link
        key="tool"
        href={seenByFindingsHref('seen_by_tool', s.tool)}
        className={`font-mono ${linkClass}`}
      >
        {s.tool_version ? `${s.tool} ${s.tool_version}` : s.tool}
      </Link>
    )
  }
  if (s.sensor?.id) {
    meta.push(
      <Link
        key="sensor"
        href={seenByFindingsHref('seen_by_sensor_id', s.sensor.id)}
        className={linkClass}
      >
        {s.sensor.name || t('findings.seenBy.sensor', 'Sensor')}
      </Link>
    )
  } else if (s.sender === 'platform') {
    meta.push(<span key="shared">{t('findings.seenBy.sharedSensor', 'Platform sensor')}</span>)
  }
  meta.push(
    <span key="first">
      {t('findings.seenBy.first', 'First')} <RelativeTime date={s.first_seen_at} />
    </span>
  )
  meta.push(
    <span key="last">
      {t('findings.seenBy.last', 'Last')} <RelativeTime date={s.last_seen_at} />
    </span>
  )
  if (s.run_id) {
    meta.push(
      <Link
        key="run"
        href={`/scans/runs?run=${encodeURIComponent(s.run_id)}`}
        className={linkClass}
      >
        {t('findings.seenBy.lastRun', 'Last run')}
      </Link>
    )
  }
  return (
    <ListItem
      className="px-0"
      title={title}
      trailing={
        <span className="flex items-center gap-1.5">
          {s.backfilled ? (
            <Badge variant="outline" className="text-xs font-normal" data-slot="seen-by-backfilled">
              {t('findings.seenBy.backfilled', 'From earlier records')}
            </Badge>
          ) : null}
          <Badge variant="outline" className="text-xs font-normal" data-slot="seen-by-count">
            {t('findings.seenBy.count', '{count, plural, one {# time} other {# times}}', {
              count: s.seen_count ?? 1,
            })}
          </Badge>
          {source ? (
            <RetireSourceButton
              compact
              source={source}
              label={[s.sensor?.name, s.sender, s.tool].filter(Boolean).join(' ')}
            />
          ) : null}
        </span>
      }
      meta={meta}
    />
  )
}

export function FindingSeenBy({ findingId, className }: { findingId: string; className?: string }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useFindingSightings(findingId)
  useSettleSignal(isLoading)

  if (isLoadFailure(error)) {
    return (
      <SectionLoadError
        title={t('findings.seenBy.loadTitle', 'who reported this finding')}
        onRetry={() => void mutate()}
        className={className}
      />
    )
  }
  const rows = data?.data ?? []
  if (error || rows.length === 0) return null

  return (
    <DetailSection
      title={t('findings.seenBy.title', 'Seen by')}
      icon={Radar}
      count={rows.length}
      className={className}
    >
      <ul className="divide-y" data-testid="finding-seen-by">
        {rows.map((s) => (
          <SightingRow
            key={`${s.channel}-${s.sensor?.id ?? ''}-${s.sender ?? ''}-${s.tool ?? ''}-${s.scan?.id ?? ''}`}
            s={s}
          />
        ))}
      </ul>
    </DetailSection>
  )
}
