'use client'

import type { ReactNode } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { useTranslation } from '@/context/i18n-provider'
import type { MobileRowSelection } from '@/features/shared/components/data-table'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { MetaLine } from '@/features/shared/components/text-layout'
import { SEVERITY_LABELS } from '@/lib/severity'
import type { ExposureEvent } from '@/lib/api/exposure-types'
import { exposureSummaryText } from '../lib/summary'
import { EXPOSURE_EVENT_TYPE_LABELS } from './exposure-table'

/**
 * An exposure on a phone. Fixed slots, plain text, one fact per element:
 *
 *   [ ] Title (two lines at most) ................. State  [...]
 *       Event type, then the summary sentence (two lines at most)
 *       Severity   Source   First seen
 *
 * The state slot is always there. A tap on the card opens the detail sheet;
 * the checkbox shows only in select mode; the menu is the table row's.
 */
export function ExposurePhoneCard({
  exposure,
  selection,
  actions,
  onOpen,
}: {
  exposure: ExposureEvent
  selection: MobileRowSelection
  /** The row menu, the same one the table row has. */
  actions: ReactNode
  onOpen: (exposure: ExposureEvent) => void
}) {
  const { t } = useTranslation()
  const summary = exposureSummaryText(exposure, t) || exposure.description || ''
  const type = t(
    `exposures.eventType.${exposure.event_type}`,
    EXPOSURE_EVENT_TYPE_LABELS[exposure.event_type]
  )
  const pending = Boolean(exposure.pending_disposition)
  return (
    <div
      data-slot="exposure-card"
      data-state={selection.selected ? 'selected' : undefined}
      className="flex cursor-pointer items-start gap-3 px-3 py-3 hover:bg-muted/50 data-[state=selected]:bg-muted"
      onClick={(e) => {
        if (
          (e.target as HTMLElement).closest('button, a[href], [role="checkbox"], [role="menuitem"]')
        )
          return
        onOpen(exposure)
      }}
    >
      {selection.selectable && (
        <Checkbox
          className="mt-0.5 shrink-0"
          checked={selection.selected}
          onCheckedChange={(v) => selection.onSelectedChange(!!v)}
          aria-label={t('exposures.table.selectRow', 'Select {title}', { title: exposure.title })}
        />
      )}
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex min-w-0 items-start gap-2">
          <p className="line-clamp-2 min-w-0 flex-1 text-body font-medium [overflow-wrap:anywhere]">
            {exposure.title}
          </p>
          <span data-slot="exposure-card-state" className="shrink-0 text-sm text-muted-foreground">
            {pending
              ? t('exposures.card.pending', 'Awaiting approval')
              : t(`exposures.state.${exposure.state}`)}
          </span>
          <div className="-my-1 shrink-0">{actions}</div>
        </div>
        <p className="line-clamp-2 text-sm text-muted-foreground">
          {summary ? t('exposures.card.typeSummary', '{type}: {summary}', { type, summary }) : type}
        </p>
        <MetaLine
          items={[
            <span key="sev">
              {t(`severity.${exposure.severity}`, SEVERITY_LABELS[exposure.severity])}
            </span>,
            exposure.source ? <span key="src">{exposure.source}</span> : null,
            <RelativeTime key="seen" date={exposure.first_seen_at} />,
          ]}
        />
      </div>
    </div>
  )
}
