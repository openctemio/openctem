'use client'

import { useTranslation } from '@/context/i18n-provider'

/**
 * Thin indeterminate bar along the top edge of a table frame while rows that
 * are already on screen are being re-read (a filter, sort or page change, or
 * a background revalidation). The parent frame must be `position: relative`;
 * the bar is absolutely positioned inside it, so it never moves the layout and
 * never covers the toolbar or the search box above the frame.
 *
 * Feedback by kind: route navigation uses the top-of-window NavProgressBar,
 * a first load uses skeletons, a data refresh uses this bar. Rendered only
 * while active, so the progressbar role exists only while there is progress.
 */
export function TableRefreshBar({ active, label }: { active: boolean; label?: string }) {
  const { t } = useTranslation()
  if (!active) return null
  return (
    <div
      data-slot="table-refresh-bar"
      role="progressbar"
      aria-label={label ?? t('common.table.refreshing', 'Refreshing')}
      className="table-refresh-bar"
    />
  )
}
