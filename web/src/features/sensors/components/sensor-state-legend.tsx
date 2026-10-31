'use client'

import { ChevronDown, CircleHelp } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { KeyValueList } from '@/features/shared/components/text-layout'
import type { SensorState } from '@/lib/api/sensor-types'

import { stateDescription, stateLabel } from '../lib/sensor-state'

/** The states a running fleet shows, in ladder order. */
const LEGEND_STATES: SensorState[] = ['online', 'degraded', 'late', 'stale', 'offline', 'idle']

/**
 * What the sensor states mean, on demand: one line under the list that opens
 * a short definition list. It used to be a paragraph of five definitions in a
 * row, which on a phone ran under the browser's toolbar and was read by
 * nobody. A native disclosure: keyboard and screen reader support come with
 * the element, and nothing loads until it opens.
 */
export function SensorStateLegend({ offlineAfter }: { offlineAfter: string }) {
  const { t } = useTranslation()
  return (
    <details data-slot="sensor-state-legend" className="group mt-3 text-xs text-muted-foreground">
      <summary className="inline-flex min-h-8 cursor-pointer list-none items-center gap-1.5 rounded-sm hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring [&::-webkit-details-marker]:hidden">
        <CircleHelp className="size-3.5 shrink-0" aria-hidden />
        {t('sensors.list.legend.toggle')}
        <ChevronDown
          className="size-3.5 shrink-0 transition-transform group-open:rotate-180 motion-reduce:transition-none"
          aria-hidden
        />
      </summary>
      <div className="mt-1 max-w-2xl space-y-2 rounded-lg border bg-card p-3">
        <p>{t('sensors.list.legend.intro')}</p>
        <KeyValueList
          size="meta"
          items={LEGEND_STATES.map((state) => ({
            key: state,
            label: stateLabel(state, t),
            value:
              state === 'offline'
                ? t('sensors.list.legend.offline', undefined, { offlineAfter })
                : stateDescription(state, t),
          }))}
        />
      </div>
    </details>
  )
}
