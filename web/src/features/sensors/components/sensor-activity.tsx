'use client'

import { forwardRef, useMemo, useState } from 'react'

import { useTranslation } from '@/context/i18n-provider'
import {
  EntityActivity,
  type EntityActivityHandle,
} from '@/features/activity/components/entity-activity'
import type { ActivityItem } from '@/features/activity/types'
import {
  ActivityTimeline,
  DetailSection,
  type ActivityTimelineEntry,
  type ActivityTimelineFilterOption,
} from '@/features/shared'
import { useSensorActivity } from '@/lib/api/sensor-hooks'
import {
  SENSOR_ACTIVITY_CATEGORIES,
  type SensorActivityCategory,
  type SensorActivityItem,
} from '@/lib/api/sensor-types'

import { describeSensorActivity, SENSOR_ACTIVITY_CHIP_KEYS, type Translate } from '../lib/activity'

function toEntry(item: SensorActivityItem, t: Translate, locale: string): ActivityTimelineEntry {
  const view = describeSensorActivity(item, t, locale)
  return {
    id: item.id,
    at: item.at,
    icon: view.icon,
    tone: view.tone,
    title: view.title,
    detail:
      view.details.length > 0 ? (
        <>
          {view.details.map((line, i) => (
            <span key={i} className="block">
              {line}
            </span>
          ))}
        </>
      ) : undefined,
    repeatCount: item.repeat_count,
    lastAt: item.last_at,
  }
}

/**
 * The drawer's Activity tab: what happened to the sensor (connection changes,
 * restarts, upgrades, protocol / tool / capacity / content changes, jobs and,
 * for owners and administrators, administrator actions), from
 * GET /sensors/{id}/activity, which every sensor reader may call.
 */
export function SensorActivity({ sensorId }: { sensorId: string }) {
  const { t, locale } = useTranslation()
  const [types, setTypes] = useState<SensorActivityCategory[]>([])
  const activity = useSensorActivity(sensorId, types)

  const entries = useMemo(
    () => activity.items.map((it) => toEntry(it, t, locale)),
    [activity.items, t, locale]
  )

  const peopleHidden = !activity.auditIncluded
  const hiddenNote = t(
    'sensors.activity.peopleHidden',
    'Administrator actions are visible to owners and administrators'
  )
  const filters: ActivityTimelineFilterOption[] = SENSOR_ACTIVITY_CATEGORIES.map((c) => {
    const [key, fallback] = SENSOR_ACTIVITY_CHIP_KEYS[c]
    return {
      value: c,
      label: t(key, fallback),
      // The API never returns administrator actions to this viewer.
      disabled: c === 'people' && peopleHidden,
      hint: c === 'people' && peopleHidden ? hiddenNote : undefined,
    }
  })

  return (
    <ActivityTimeline
      entries={entries}
      filters={filters}
      selectedFilters={types}
      onSelectedFiltersChange={(next) =>
        setTypes(
          SENSOR_ACTIVITY_CATEGORIES.filter(
            (c) => next.includes(c) && !(c === 'people' && peopleHidden)
          )
        )
      }
      loading={activity.isLoading}
      error={activity.error}
      errorTitle={t('sensors.activity.errorTitle', 'sensor activity')}
      onRetry={() => void activity.retry()}
      hasMore={activity.hasMore}
      loadingMore={activity.isLoadingMore}
      onLoadMore={() => void activity.loadMore()}
      emptyTitle={t('sensors.activity.emptyTitle', 'No activity yet')}
      emptyDescription={t(
        'sensors.activity.emptyDescription',
        'Restarts, upgrades, protocol and tool changes, connection changes, jobs and administrator actions will appear here as they happen.'
      )}
      notice={peopleHidden ? hiddenNote : undefined}
    />
  )
}

/**
 * The drawer's activity: on the Overview, a one-line summary of the latest
 * event that opens the shared ActivityPanel, which holds the full log above
 * (chips, cursor pages). Same trigger + panel as every other activity feed;
 * there is no Activity tab.
 */
export const SensorRecentActivity = forwardRef<
  EntityActivityHandle,
  { sensorId: string; sensorName?: string }
>(function SensorRecentActivity({ sensorId, sensorName }, ref) {
  const { t, locale } = useTranslation()
  const { items, isLoading, error } = useSensorActivity(sensorId, [], { limit: 5 })
  const events = useMemo(
    () =>
      items.slice(0, 5).map((it): ActivityItem => {
        const view = describeSensorActivity(it, t, locale)
        const actor = it.type === 'audit' && it.actor && it.actor !== 'system' ? it.actor : ''
        const repeated = (it.repeat_count ?? 1) > 1 ? ` ×${it.repeat_count}` : ''
        return {
          kind: 'event',
          id: it.id,
          at: it.last_at && repeated ? it.last_at : it.at,
          // Sensor events read as sentences ("Went offline"); only an
          // administrator action names who did it.
          actor: { name: actor, kind: actor ? 'user' : 'system' },
          icon: view.icon,
          tone: view.tone,
          summary: `${view.title}${repeated}`,
        }
      }),
    [items, t, locale]
  )

  return (
    <DetailSection title={t('sensors.activity.title', 'Activity')}>
      <EntityActivity
        ref={ref}
        entityKey={`sensor:${sensorId}`}
        subject={sensorName}
        items={events}
        loading={isLoading}
        error={error}
        urlParam={false}
        triggerHeadline={
          error
            ? t('sensors.activity.recentError', 'Could not load the activity.')
            : t('sensors.activity.latest', 'Latest events')
        }
        customBody={<SensorActivity sensorId={sensorId} />}
      />
    </DetailSection>
  )
})
