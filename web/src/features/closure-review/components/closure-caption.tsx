'use client'

import { RefreshButton } from '@/components/list-page-parts'
import { useTranslation } from '@/context/i18n-provider'
import { formatCount } from '@/lib/format-metric'

/**
 * The line under a closes list: how many findings it holds and Refresh. The
 * tabs above already name the view, so none of this takes a row above the
 * table.
 */
export function ClosureCaption({
  total,
  loading,
  refreshing,
  onRefresh,
}: {
  total: number
  loading: boolean
  refreshing: boolean
  onRefresh: () => void
}) {
  const { t, locale } = useTranslation()
  return (
    <div
      data-testid="closure-caption"
      className="flex min-w-0 flex-wrap items-center justify-between gap-x-4 gap-y-1 text-meta text-muted-foreground"
    >
      <span className="tabular-nums" aria-live="polite">
        {loading
          ? null
          : t(
              'findings.closureReview.total',
              '{count, plural, one {# finding} other {# findings}}',
              { count: formatCount(total, locale) }
            )}
      </span>
      <RefreshButton
        onClick={onRefresh}
        loading={refreshing}
        label={t('findings.closureReview.refresh', 'Refresh')}
      />
    </div>
  )
}
