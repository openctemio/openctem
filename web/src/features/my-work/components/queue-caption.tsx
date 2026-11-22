'use client'

import { RefreshButton } from '@/components/list-page-parts'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { useTranslation } from '@/context/i18n-provider'
import { formatCount } from '@/lib/format-metric'

/**
 * The line under a My Work queue: how much of it is on screen, when it was
 * read, and Refresh. One caption for every tab, so none of this
 * takes a row above the list.
 */
export function QueueCaption({
  shown,
  total,
  asOf,
  onRefresh,
}: {
  shown: number
  total?: number
  asOf?: string
  onRefresh: () => void
}) {
  const { t, locale } = useTranslation()
  const note =
    total !== undefined && shown > 0 && total > shown
      ? t('myWork.topOf', 'Top {shown} of {total}', { shown, total: formatCount(total, locale) })
      : null
  return (
    <div
      data-testid="my-work-caption"
      className="flex min-w-0 flex-wrap items-center justify-between gap-x-4 gap-y-1 text-meta text-muted-foreground"
    >
      <span className="tabular-nums" aria-live="polite">
        {note}
      </span>
      <div className="ms-auto flex items-center gap-2">
        {asOf && (
          <span className="whitespace-nowrap">
            {t('myWork.updated', 'Updated')} <RelativeTime date={asOf} />
          </span>
        )}
        <RefreshButton onClick={onRefresh} label={t('myWork.refresh', 'Refresh')} />
      </div>
    </div>
  )
}
